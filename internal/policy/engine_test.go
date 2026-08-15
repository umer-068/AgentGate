package policy

import (
	"context"
	"os"
	"testing"

	"github.com/naseerumer/agentgate/pkg/mcp"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(context.Background(), "./policies/policy.yaml", "")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestNewEngine_RejectsEmptyBundlePath(t *testing.T) {
	if _, err := NewEngine(context.Background(), "", ""); err == nil {
		t.Fatal("expected error for empty bundlePath")
	}
}

func TestNewEngine_RejectsMissingFile(t *testing.T) {
	if _, err := NewEngine(context.Background(), "./does-not-exist.yaml", ""); err == nil {
		t.Fatal("expected error for nonexistent bundle path")
	}
}

func TestNewEngine_RejectsMalformedRule(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bad.yaml"
	if err := os.WriteFile(path, []byte("deny_rules:\n  - reason: missing tool and pattern\n"), 0o600); err != nil {
		t.Fatalf("write temp policy: %v", err)
	}
	if _, err := NewEngine(context.Background(), path, ""); err == nil {
		t.Fatal("expected error for deny rule missing tool/resource_pattern")
	}
}

func TestEvaluate_AllowsMatchingScope(t *testing.T) {
	e := newTestEngine(t)
	call := mcp.ToolCall{Tool: "github", Action: "read", Resource: "repo/agentgate"}

	decision, err := e.Evaluate(context.Background(), call, []string{"tool:github:read"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allow, got deny with reason %q", decision.Reason)
	}
	if decision.PolicyID != "scope-allow" {
		t.Errorf("expected policy_id scope-allow, got %s", decision.PolicyID)
	}
}

func TestEvaluate_AllowsWildcardAction(t *testing.T) {
	e := newTestEngine(t)
	call := mcp.ToolCall{Tool: "github", Action: "write", Resource: "repo/agentgate"}

	decision, err := e.Evaluate(context.Background(), call, []string{"tool:github:*"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allow via wildcard scope, got deny with reason %q", decision.Reason)
	}
}

func TestEvaluate_DeniesWithoutMatchingScope(t *testing.T) {
	e := newTestEngine(t)
	call := mcp.ToolCall{Tool: "github", Action: "delete", Resource: "repo/agentgate"}

	decision, err := e.Evaluate(context.Background(), call, []string{"tool:github:read"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected deny for action outside granted scope")
	}
	if decision.PolicyID != "default-deny" {
		t.Errorf("expected policy_id default-deny, got %s", decision.PolicyID)
	}
}

func TestEvaluate_ExplicitDenyOverridesScope(t *testing.T) {
	e := newTestEngine(t)
	// Even a wildcard scope must not bypass the explicit deny rule on
	// prod-* S3 buckets defined in policies/policy.yaml.
	call := mcp.ToolCall{Tool: "aws-s3", Action: "write", Resource: "prod-billing-exports"}

	decision, err := e.Evaluate(context.Background(), call, []string{"tool:aws-s3:*"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected explicit deny rule to override wildcard scope")
	}
	if decision.PolicyID != "explicit-deny" {
		t.Errorf("expected policy_id explicit-deny, got %s", decision.PolicyID)
	}
}

func TestEvaluate_ShellAlwaysDenied(t *testing.T) {
	e := newTestEngine(t)
	call := mcp.ToolCall{Tool: "shell", Action: "exec", Resource: "rm -rf /"}

	decision, err := e.Evaluate(context.Background(), call, []string{"tool:shell:*"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected shell tool to always be denied by org-wide policy")
	}
}

func TestEvaluate_NamespacedGlobPattern(t *testing.T) {
	e := newTestEngine(t)
	call := mcp.ToolCall{Tool: "kubernetes", Action: "apply", Resource: "namespace/prod/deployments/api"}

	decision, err := e.Evaluate(context.Background(), call, []string{"tool:kubernetes:*"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected prod namespace deny rule to match nested resource path")
	}
}

func TestEvaluate_NoScopesDeniesByDefault(t *testing.T) {
	e := newTestEngine(t)
	call := mcp.ToolCall{Tool: "github", Action: "read", Resource: "repo/agentgate"}

	decision, err := e.Evaluate(context.Background(), call, nil)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected deny when no scopes are present")
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"prod-*", "prod-billing", true},
		{"prod-*", "staging-billing", false},
		{"*", "anything", true},
		{"exact", "exact", true},
		{"exact", "not-exact", false},
		{"namespace/prod/*", "namespace/prod/deployments/api", true},
		{"namespace/prod/*", "namespace/staging/deployments/api", false},
		{"*.internal", "api.internal", true},
		{"*.internal", "api.external", false},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
	}
	for _, tc := range cases {
		if got := globMatch(tc.pattern, tc.s); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}
