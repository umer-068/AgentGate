package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/umer-068/AgentGate/pkg/mcp"
)

func TestNewHTTPForwarder_RejectsEmptyTargets(t *testing.T) {
	if _, err := NewHTTPForwarder(nil, time.Second); err == nil {
		t.Fatal("expected error for empty targets map")
	}
}

func TestNewHTTPForwarder_RejectsInvalidURL(t *testing.T) {
	_, err := NewHTTPForwarder(map[string]string{"github": "://not-a-url"}, time.Second)
	if err == nil {
		t.Fatal("expected error for invalid upstream URL")
	}
}

func TestForward_UnknownTool(t *testing.T) {
	fw, err := NewHTTPForwarder(map[string]string{"github": "https://example.com"}, time.Second)
	if err != nil {
		t.Fatalf("NewHTTPForwarder: %v", err)
	}
	_, _, err = fw.Forward(context.Background(), "unknown-tool", mcp.ToolCall{})
	if err == nil {
		t.Fatal("expected error for tool with no configured upstream")
	}
}

func TestForward_RelaysRequestAndDecodesResponse(t *testing.T) {
	var gotMethod, gotPath, gotAgentHeader string
	var gotBody map[string]any

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAgentHeader = r.Header.Get("X-AgentGate-Agent-ID")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"created": true})
	}))
	defer upstream.Close()

	fw, err := NewHTTPForwarder(map[string]string{"github": upstream.URL}, time.Second)
	if err != nil {
		t.Fatalf("NewHTTPForwarder: %v", err)
	}

	call := mcp.ToolCall{
		AgentID:  "agent-1",
		Tool:     "github",
		Action:   "write",
		Resource: "repos/octocat/hello",
		Params:   map[string]any{"title": "test issue"},
	}

	status, body, err := fw.Forward(context.Background(), "github", call)
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if status != http.StatusCreated {
		t.Errorf("expected 201, got %d", status)
	}
	if body["created"] != true {
		t.Errorf("unexpected body: %v", body)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("expected POST upstream, got %s", gotMethod)
	}
	if gotPath != "/repos/octocat/hello" {
		t.Errorf("expected path /repos/octocat/hello, got %s", gotPath)
	}
	if gotAgentHeader != "agent-1" {
		t.Errorf("expected agent id header agent-1, got %s", gotAgentHeader)
	}
	if gotBody["title"] != "test issue" {
		t.Errorf("expected params relayed as body, got %v", gotBody)
	}
}

func TestForward_NonJSONUpstreamResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("plain text response"))
	}))
	defer upstream.Close()

	fw, err := NewHTTPForwarder(map[string]string{"legacy": upstream.URL}, time.Second)
	if err != nil {
		t.Fatalf("NewHTTPForwarder: %v", err)
	}

	status, body, err := fw.Forward(context.Background(), "legacy", mcp.ToolCall{Resource: "x"})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	if body["raw"] != "plain text response" {
		t.Errorf("expected raw text fallback, got %v", body)
	}
}
