package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/umer-068/AgentGate/internal/audit"
	"github.com/umer-068/AgentGate/internal/identity"
	"github.com/umer-068/AgentGate/pkg/mcp"
)

// --- fakes -------------------------------------------------------------

type fakeVerifier struct {
	sessions map[string]*identity.Session
}

func (f *fakeVerifier) Verify(token string) (*identity.Session, error) {
	s, ok := f.sessions[token]
	if !ok {
		return nil, identity.ErrInvalidToken
	}
	return s, nil
}

type fakeEngine struct {
	decision mcp.Decision
	err      error
	lastCall mcp.ToolCall
}

func (f *fakeEngine) Evaluate(_ context.Context, call mcp.ToolCall, _ []string) (mcp.Decision, error) {
	f.lastCall = call
	return f.decision, f.err
}

type fakeAuditor struct {
	entries []audit.Entry
	failAll bool
}

func (f *fakeAuditor) Record(_ context.Context, e audit.Entry) error {
	if f.failAll {
		return errors.New("simulated audit failure")
	}
	f.entries = append(f.entries, e)
	return nil
}

type fakeForwarder struct {
	statusCode int
	body       map[string]any
	err        error
	called     bool
}

func (f *fakeForwarder) Forward(_ context.Context, _ string, _ mcp.ToolCall) (int, map[string]any, error) {
	f.called = true
	return f.statusCode, f.body, f.err
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(bytesDiscard{}, nil))
}

type bytesDiscard struct{}

func (bytesDiscard) Write(p []byte) (int, error) { return len(p), nil }

// --- constructor validation ---------------------------------------------

func TestNew_RejectsNilCollaborators(t *testing.T) {
	v := &fakeVerifier{}
	e := &fakeEngine{}
	a := &fakeAuditor{}
	fw := &fakeForwarder{}
	l := testLogger()

	if _, err := New(nil, e, a, fw, l); err == nil {
		t.Error("expected error for nil verifier")
	}
	if _, err := New(v, nil, a, fw, l); err == nil {
		t.Error("expected error for nil engine")
	}
	if _, err := New(v, e, nil, fw, l); err == nil {
		t.Error("expected error for nil auditor")
	}
	if _, err := New(v, e, a, nil, l); err == nil {
		t.Error("expected error for nil forwarder")
	}
	if _, err := New(v, e, a, fw, nil); err == nil {
		t.Error("expected error for nil logger")
	}
}

// --- request handling ----------------------------------------------------

func newTestGateway(t *testing.T, verifier *fakeVerifier, engine *fakeEngine, auditor *fakeAuditor, forwarder *fakeForwarder) *Gateway {
	t.Helper()
	g, err := New(verifier, engine, auditor, forwarder, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func doToolCall(t *testing.T, g *Gateway, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/tool-call", bytes.NewReader(raw))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	g.Router().ServeHTTP(rec, req)
	return rec
}

func TestHandleToolCall_MissingAuthHeader(t *testing.T) {
	g := newTestGateway(t, &fakeVerifier{}, &fakeEngine{}, &fakeAuditor{}, &fakeForwarder{})
	rec := doToolCall(t, g, "", toolCallRequest{Tool: "github", Action: "read", Resource: "r"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestHandleToolCall_InvalidToken(t *testing.T) {
	g := newTestGateway(t, &fakeVerifier{sessions: map[string]*identity.Session{}}, &fakeEngine{}, &fakeAuditor{}, &fakeForwarder{})
	rec := doToolCall(t, g, "bogus-token", toolCallRequest{Tool: "github", Action: "read", Resource: "r"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestHandleToolCall_MissingFields(t *testing.T) {
	verifier := &fakeVerifier{sessions: map[string]*identity.Session{"tok": {AgentID: "agent-1"}}}
	g := newTestGateway(t, verifier, &fakeEngine{}, &fakeAuditor{}, &fakeForwarder{})
	rec := doToolCall(t, g, "tok", toolCallRequest{Tool: "github"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandleToolCall_DeniedDoesNotForward(t *testing.T) {
	verifier := &fakeVerifier{sessions: map[string]*identity.Session{"tok": {AgentID: "agent-1", Scopes: []string{"tool:github:read"}}}}
	engine := &fakeEngine{decision: mcp.Decision{Allowed: false, Reason: "no matching rule", PolicyID: "default-deny"}}
	auditor := &fakeAuditor{}
	forwarder := &fakeForwarder{}
	g := newTestGateway(t, verifier, engine, auditor, forwarder)

	rec := doToolCall(t, g, "tok", toolCallRequest{Tool: "github", Action: "delete", Resource: "repo/x"})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if forwarder.called {
		t.Error("forwarder must not be called for a denied decision")
	}
	if len(auditor.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(auditor.entries))
	}
	if auditor.entries[0].Allowed {
		t.Error("expected audited entry to record denial")
	}
}

func TestHandleToolCall_AllowedForwardsAndReturnsResult(t *testing.T) {
	verifier := &fakeVerifier{sessions: map[string]*identity.Session{"tok": {AgentID: "agent-1", Scopes: []string{"tool:github:read"}}}}
	engine := &fakeEngine{decision: mcp.Decision{Allowed: true, Reason: "scope match", PolicyID: "scope-allow"}}
	auditor := &fakeAuditor{}
	forwarder := &fakeForwarder{statusCode: 200, body: map[string]any{"ok": true}}
	g := newTestGateway(t, verifier, engine, auditor, forwarder)

	rec := doToolCall(t, g, "tok", toolCallRequest{Tool: "github", Action: "read", Resource: "repo/x"})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !forwarder.called {
		t.Error("expected forwarder to be called for an allowed decision")
	}
	if len(auditor.entries) != 1 || !auditor.entries[0].Allowed {
		t.Fatal("expected one audit entry recording allow")
	}

	var result mcp.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !result.Decision.Allowed {
		t.Error("expected decision.allowed=true in response body")
	}
}

func TestHandleToolCall_PolicyEngineErrorReturns500(t *testing.T) {
	verifier := &fakeVerifier{sessions: map[string]*identity.Session{"tok": {AgentID: "agent-1"}}}
	engine := &fakeEngine{err: errors.New("boom")}
	g := newTestGateway(t, verifier, engine, &fakeAuditor{}, &fakeForwarder{})

	rec := doToolCall(t, g, "tok", toolCallRequest{Tool: "github", Action: "read", Resource: "r"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestHandleToolCall_ForwardErrorReturns502(t *testing.T) {
	verifier := &fakeVerifier{sessions: map[string]*identity.Session{"tok": {AgentID: "agent-1"}}}
	engine := &fakeEngine{decision: mcp.Decision{Allowed: true}}
	forwarder := &fakeForwarder{err: errors.New("upstream down")}
	g := newTestGateway(t, verifier, engine, &fakeAuditor{}, forwarder)

	rec := doToolCall(t, g, "tok", toolCallRequest{Tool: "github", Action: "read", Resource: "r"})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
}

func TestHandleToolCall_AuditFailureDoesNotBlockResponse(t *testing.T) {
	verifier := &fakeVerifier{sessions: map[string]*identity.Session{"tok": {AgentID: "agent-1"}}}
	engine := &fakeEngine{decision: mcp.Decision{Allowed: true}}
	auditor := &fakeAuditor{failAll: true}
	forwarder := &fakeForwarder{statusCode: 200, body: map[string]any{}}
	g := newTestGateway(t, verifier, engine, auditor, forwarder)

	rec := doToolCall(t, g, "tok", toolCallRequest{Tool: "github", Action: "read", Resource: "r"})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected audit-store failure to degrade gracefully, got %d", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	g := newTestGateway(t, &fakeVerifier{}, &fakeEngine{}, &fakeAuditor{}, &fakeForwarder{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	g.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestHandleToolCall_RejectsUnknownFields(t *testing.T) {
	verifier := &fakeVerifier{sessions: map[string]*identity.Session{"tok": {AgentID: "agent-1"}}}
	g := newTestGateway(t, verifier, &fakeEngine{}, &fakeAuditor{}, &fakeForwarder{})

	req := httptest.NewRequest(http.MethodPost, "/v1/tool-call", bytes.NewReader([]byte(`{"tool":"github","action":"read","resource":"r","unexpected":"x"}`)))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	g.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown field, got %d", rec.Code)
	}
}
