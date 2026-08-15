// Package gateway implements AgentGate's HTTP entrypoint: the zero-trust
// boundary between an AI agent and the tools/APIs it's allowed to call.
//
// Request flow for every tool call:
//
//  1. Verify the bearer token (short-lived session credential, see
//     internal/identity) and recover the calling agent's identity + scopes.
//  2. Evaluate the requested tool call against the policy bundle
//     (internal/policy - deny-rule-then-scope semantics, with a Rego
//     reference implementation in examples/policies/opa-reference), which
//     may consult explicit deny rules that no scope can override.
//  3. Record the decision to the immutable audit trail and structured logs
//     (internal/audit) *before* acting on it, so a crash mid-forward can
//     never produce an unaudited action.
//  4. If allowed, forward the call to the configured upstream for that
//     tool and relay the response; if denied, return 403 with the policy's
//     stated reason.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/naseerumer/agentgate/internal/audit"
	"github.com/naseerumer/agentgate/internal/identity"
	"github.com/naseerumer/agentgate/pkg/mcp"
)

// PolicyEngine is the subset of policy.Engine's behavior the gateway
// depends on, so tests can substitute a fake without loading a real Rego
// bundle.
type PolicyEngine interface {
	Evaluate(ctx context.Context, call mcp.ToolCall, scopes []string) (mcp.Decision, error)
}

// TokenVerifier is the subset of identity.Issuer's behavior the gateway
// depends on.
type TokenVerifier interface {
	Verify(token string) (*identity.Session, error)
}

// AuditRecorder is the subset of audit.Store's behavior the gateway depends
// on.
type AuditRecorder interface {
	Record(ctx context.Context, e audit.Entry) error
}

// Forwarder performs the actual upstream call once a request has been
// allowed. Kept as an interface so tests can avoid real network calls.
type Forwarder interface {
	Forward(ctx context.Context, tool string, call mcp.ToolCall) (statusCode int, body map[string]any, err error)
}

// Gateway wires identity verification, policy evaluation, audit recording,
// and upstream forwarding into a single HTTP handler.
type Gateway struct {
	verifier  TokenVerifier
	engine    PolicyEngine
	auditor   AuditRecorder
	forwarder Forwarder
	logger    *slog.Logger
	now       func() time.Time
}

// New builds a Gateway from its collaborators. All arguments are required.
func New(verifier TokenVerifier, engine PolicyEngine, auditor AuditRecorder, forwarder Forwarder, logger *slog.Logger) (*Gateway, error) {
	if verifier == nil {
		return nil, errors.New("gateway: verifier must not be nil")
	}
	if engine == nil {
		return nil, errors.New("gateway: engine must not be nil")
	}
	if auditor == nil {
		return nil, errors.New("gateway: auditor must not be nil")
	}
	if forwarder == nil {
		return nil, errors.New("gateway: forwarder must not be nil")
	}
	if logger == nil {
		return nil, errors.New("gateway: logger must not be nil")
	}
	return &Gateway{
		verifier:  verifier,
		engine:    engine,
		auditor:   auditor,
		forwarder: forwarder,
		logger:    logger,
		now:       time.Now,
	}, nil
}

// Router builds the HTTP mux exposing the gateway's endpoints.
func (g *Gateway) Router() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", g.handleHealthz)
	mux.HandleFunc("POST /v1/tool-call", g.handleToolCall)
	return mux
}

func (g *Gateway) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

type toolCallRequest struct {
	Tool     string         `json:"tool"`
	Action   string         `json:"action"`
	Resource string         `json:"resource"`
	Params   map[string]any `json:"params,omitempty"`
}

func (g *Gateway) handleToolCall(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	session, err := g.authenticate(r)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req toolCallRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Tool == "" || req.Action == "" || req.Resource == "" {
		writeJSONError(w, http.StatusBadRequest, "tool, action, and resource are required")
		return
	}

	call := mcp.ToolCall{
		AgentID:     session.AgentID,
		Tool:        req.Tool,
		Action:      req.Action,
		Resource:    req.Resource,
		Params:      req.Params,
		RequestedAt: g.now(),
	}

	decision, err := g.engine.Evaluate(ctx, call, session.Scopes)
	if err != nil {
		g.logger.Error("policy evaluation failed", "error", err, "agent_id", session.AgentID, "tool", call.Tool)
		writeJSONError(w, http.StatusInternalServerError, "policy evaluation failed")
		return
	}

	g.audit(ctx, call, decision)

	if !decision.Allowed {
		writeJSON(w, http.StatusForbidden, mcp.Result{Decision: decision})
		return
	}

	statusCode, body, err := g.forwarder.Forward(ctx, call.Tool, call)
	if err != nil {
		g.logger.Error("upstream forward failed", "error", err, "agent_id", session.AgentID, "tool", call.Tool)
		writeJSONError(w, http.StatusBadGateway, "upstream call failed")
		return
	}

	writeJSON(w, http.StatusOK, mcp.Result{Decision: decision, StatusCode: statusCode, Body: body})
}

func (g *Gateway) authenticate(r *http.Request) (*identity.Session, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, errors.New("missing Authorization header")
	}
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || token == "" {
		return nil, errors.New("authorization header must be a Bearer token")
	}
	session, err := g.verifier.Verify(token)
	if err != nil {
		return nil, fmt.Errorf("invalid session token: %w", err)
	}
	return session, nil
}

func (g *Gateway) audit(ctx context.Context, call mcp.ToolCall, decision mcp.Decision) {
	entry := audit.Entry{
		Timestamp: call.RequestedAt,
		AgentID:   call.AgentID,
		Tool:      call.Tool,
		Action:    call.Action,
		Resource:  call.Resource,
		Allowed:   decision.Allowed,
		Reason:    decision.Reason,
		PolicyID:  decision.PolicyID,
	}

	logLevel := slog.LevelInfo
	if !decision.Allowed {
		logLevel = slog.LevelWarn
	}
	g.logger.Log(ctx, logLevel, "tool call decision",
		"agent_id", call.AgentID, "tool", call.Tool, "action", call.Action,
		"resource", call.Resource, "allowed", decision.Allowed,
		"reason", decision.Reason, "policy_id", decision.PolicyID,
	)

	if err := g.auditor.Record(ctx, entry); err != nil {
		// The audit *log line* above already captured the decision, so a
		// failure to persist to the durable store is a warning, not a
		// reason to fail the request - but it must never be silent.
		g.logger.Error("failed to persist audit trail entry", "error", err, "agent_id", call.AgentID)
	}
}

func decodeJSONBody(r *http.Request, dst any) error {
	defer func() { _, _ = io.Copy(io.Discard, r.Body); _ = r.Body.Close() }()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
