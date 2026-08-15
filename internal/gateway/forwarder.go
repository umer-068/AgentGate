package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/umer-068/AgentGate/pkg/mcp"
)

// HTTPForwarder forwards allowed tool calls to a configured upstream base
// URL per tool name. It never receives calls the policy engine denied - by
// construction, the gateway only invokes Forward after an "allow" decision.
type HTTPForwarder struct {
	targets map[string]string
	client  *http.Client
}

// NewHTTPForwarder builds a forwarder from a tool-name -> base-URL map.
func NewHTTPForwarder(targets map[string]string, timeout time.Duration) (*HTTPForwarder, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("gateway: forwarder requires at least one upstream target")
	}
	for tool, base := range targets {
		if _, err := url.Parse(base); err != nil {
			return nil, fmt.Errorf("gateway: invalid upstream URL for tool %q: %w", tool, err)
		}
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &HTTPForwarder{
		targets: targets,
		client:  &http.Client{Timeout: timeout},
	}, nil
}

// Forward relays an allowed tool call's Params as a JSON POST body to the
// upstream registered for the call's tool, returning the upstream's status
// code and decoded JSON body.
func (f *HTTPForwarder) Forward(ctx context.Context, tool string, call mcp.ToolCall) (int, map[string]any, error) {
	base, ok := f.targets[tool]
	if !ok {
		return 0, nil, fmt.Errorf("gateway: no upstream configured for tool %q", tool)
	}

	payload, err := json.Marshal(call.Params)
	if err != nil {
		return 0, nil, fmt.Errorf("gateway: encode params: %w", err)
	}

	target := strings.TrimRight(base, "/") + "/" + strings.TrimLeft(call.Resource, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("gateway: build upstream request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AgentGate-Agent-ID", call.AgentID)
	req.Header.Set("X-AgentGate-Action", call.Action)

	resp, err := f.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("gateway: upstream request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB cap
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("gateway: read upstream response: %w", err)
	}

	var body map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			// Non-JSON upstream response: still return the status code and
			// surface the raw text rather than failing the whole call.
			body = map[string]any{"raw": string(raw)}
		}
	}

	return resp.StatusCode, body, nil
}
