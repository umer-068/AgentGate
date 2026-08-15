// Package mcp defines the minimal request/response vocabulary AgentGate uses
// to reason about tool calls made by AI agents against MCP servers or
// arbitrary backend APIs. It intentionally models a subset of the Model
// Context Protocol's tool-call shape rather than importing the full spec, so
// AgentGate can sit in front of any JSON-RPC-ish tool-calling backend, not
// just a specific MCP server implementation.
package mcp

import "time"

// ToolCall represents a single action an agent is attempting to perform.
// AgentGate makes allow/deny decisions against this struct, so every field
// that a policy might reasonably need to inspect belongs here rather than
// buried in an opaque payload.
type ToolCall struct {
	// AgentID identifies the calling agent's session (set by the gateway
	// after token verification, never trusted from the client directly).
	AgentID string `json:"agent_id"`

	// Tool is the logical tool/server name, e.g. "aws-s3", "github", "shell".
	Tool string `json:"tool"`

	// Action is the operation being requested, e.g. "read", "write", "delete".
	Action string `json:"action"`

	// Resource is the target of the action, e.g. an S3 bucket ARN, a repo
	// path, or a Kubernetes object reference. Free-form by design: policies
	// match on it with glob/prefix rules rather than a fixed schema.
	Resource string `json:"resource"`

	// Params carries the tool-specific request payload. AgentGate does not
	// interpret it, only forwards it once a call is allowed.
	Params map[string]any `json:"params,omitempty"`

	// RequestedAt is set by the gateway at receipt time and used for replay
	// windows and anomaly-rate calculations.
	RequestedAt time.Time `json:"requested_at"`
}

// Decision is the outcome of evaluating a ToolCall against policy.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	// PolicyID identifies which policy rule produced the decision, for audit
	// traceability.
	PolicyID string `json:"policy_id,omitempty"`
}

// Result is what AgentGate returns to the caller after forwarding an allowed
// call, or immediately for a denied one.
type Result struct {
	Decision   Decision       `json:"decision"`
	StatusCode int            `json:"status_code,omitempty"`
	Body       map[string]any `json:"body,omitempty"`
}
