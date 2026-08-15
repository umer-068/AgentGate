// Package policy evaluates every AgentGate tool call against a declarative
// policy bundle: explicit deny rules that no scope can override, then
// scope-based allow rules, then default-deny.
//
// Engineering note: production-grade policy engines for this problem are
// normally built on Open Policy Agent / Rego so that policy authors get a
// real language, a test framework, and bundle signing/distribution. This
// package is a deliberately dependency-light, native-Go evaluator with
// identical decision semantics, chosen so AgentGate builds fully offline
// with no external module resolution beyond GitHub-hosted, vanity-free
// dependencies (see docs/adr/0001-go-over-rust-for-mvp.md for the full
// rationale). The equivalent policy expressed in real Rego lives in
// examples/policies/opa-reference, and the Engine type here implements the
// same gateway.PolicyEngine interface a real OPA-backed engine would, so
// swapping evaluators later touches this package only.
package policy

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/naseerumer/agentgate/pkg/mcp"
)

// DenyRule is an org-wide ceiling: if a tool call's tool matches and its
// resource matches resource_pattern, the call is denied regardless of the
// requesting agent's granted scopes.
type DenyRule struct {
	Tool            string `yaml:"tool"`
	ResourcePattern string `yaml:"resource_pattern"`
	Reason          string `yaml:"reason"`
}

// Bundle is the on-disk policy document.
type Bundle struct {
	DenyRules []DenyRule `yaml:"deny_rules"`
}

// Engine evaluates ToolCalls against a loaded Bundle.
type Engine struct {
	bundle Bundle
}

// NewEngine loads and validates the policy bundle at bundlePath.
//
// The query parameter is accepted (rather than dropped) to keep this
// constructor's signature compatible with a future OPA-backed
// implementation, which would use it as the Rego query path
// (e.g. "data.agentgate.authz.decision"); the native evaluator ignores it.
func NewEngine(_ context.Context, bundlePath, _ string) (*Engine, error) {
	if bundlePath == "" {
		return nil, fmt.Errorf("policy: bundlePath must not be empty")
	}

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("policy: read bundle at %s: %w", bundlePath, err)
	}

	var bundle Bundle
	if err := yaml.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("policy: parse bundle at %s: %w", bundlePath, err)
	}

	for i, rule := range bundle.DenyRules {
		if rule.Tool == "" || rule.ResourcePattern == "" {
			return nil, fmt.Errorf("policy: deny_rules[%d] must set tool and resource_pattern", i)
		}
	}

	return &Engine{bundle: bundle}, nil
}

// Evaluate runs the policy bundle against a tool call and the requesting
// session's scopes, returning the resulting Decision.
func (e *Engine) Evaluate(_ context.Context, call mcp.ToolCall, scopes []string) (mcp.Decision, error) {
	for _, rule := range e.bundle.DenyRules {
		if rule.Tool != call.Tool {
			continue
		}
		if globMatch(rule.ResourcePattern, call.Resource) {
			return mcp.Decision{
				Allowed:  false,
				Reason:   rule.Reason,
				PolicyID: "explicit-deny",
			}, nil
		}
	}

	for _, scope := range scopes {
		if scopeMatches(scope, call.Tool, call.Action) {
			return mcp.Decision{
				Allowed:  true,
				Reason:   fmt.Sprintf("scope %q grants %s on tool %q", scope, call.Action, call.Tool),
				PolicyID: "scope-allow",
			}, nil
		}
	}

	return mcp.Decision{
		Allowed:  false,
		Reason:   "no matching allow rule",
		PolicyID: "default-deny",
	}, nil
}

// scopeMatches checks a scope string of the form "tool:<tool>:<action>" (or
// "tool:<tool>:*") against a requested tool/action pair.
func scopeMatches(scope, tool, action string) bool {
	parts := strings.SplitN(scope, ":", 3)
	if len(parts) != 3 || parts[0] != "tool" {
		return false
	}
	if parts[1] != tool {
		return false
	}
	return parts[2] == "*" || parts[2] == action
}

// globMatch reports whether s matches pattern, where pattern may contain at
// most one "*" wildcard segment structure of the form "prefix*middle*suffix"
// (any number of "*" segments), each "*" matching zero or more characters,
// including "/". This intentionally mirrors OPA's glob.match semantics with
// an empty delimiter set (see examples/policies/opa-reference), so the
// native evaluator and the Rego reference implementation agree on the same
// inputs.
func globMatch(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}

	parts := strings.Split(pattern, "*")

	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]

	last := parts[len(parts)-1]
	if !strings.HasSuffix(s, last) {
		return false
	}
	s = s[:len(s)-len(last)]

	for _, mid := range parts[1 : len(parts)-1] {
		if mid == "" {
			continue
		}
		idx := strings.Index(s, mid)
		if idx == -1 {
			return false
		}
		s = s[idx+len(mid):]
	}
	return true
}
