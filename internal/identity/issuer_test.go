package identity

import (
	"strings"
	"testing"
	"time"
)

func validKey() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func TestNewIssuer_ValidatesInputs(t *testing.T) {
	cases := []struct {
		name string
		key  []byte
		iss  string
		ttl  time.Duration
	}{
		{"short key", []byte("tooshort"), "agentgate", time.Minute},
		{"empty issuer", validKey(), "", time.Minute},
		{"zero ttl", validKey(), "agentgate", 0},
		{"negative ttl", validKey(), "agentgate", -time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewIssuer(tc.key, tc.iss, tc.ttl); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestIssueAndVerify_RoundTrip(t *testing.T) {
	iss, err := NewIssuer(validKey(), "agentgate", 15*time.Minute)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	token, err := iss.Issue("agent-123", []string{"tool:github:read"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if token == "" || !strings.Contains(token, ".") {
		t.Fatalf("expected a JWT-shaped token, got %q", token)
	}

	sess, err := iss.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sess.AgentID != "agent-123" {
		t.Errorf("expected agent-123, got %s", sess.AgentID)
	}
	if len(sess.Scopes) != 1 || sess.Scopes[0] != "tool:github:read" {
		t.Errorf("unexpected scopes: %v", sess.Scopes)
	}
}

func TestIssue_RejectsEmptyAgentID(t *testing.T) {
	iss, _ := NewIssuer(validKey(), "agentgate", time.Minute)
	if _, err := iss.Issue("", nil); err == nil {
		t.Fatal("expected error for empty agentID")
	}
}

func TestVerify_RejectsExpiredToken(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	iss, err := NewIssuer(validKey(), "agentgate", time.Minute)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	iss.now = func() time.Time { return base }

	token, err := iss.Issue("agent-123", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Advance time past expiry.
	iss.now = func() time.Time { return base.Add(2 * time.Minute) }

	if _, err := iss.Verify(token); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for expired token, got %v", err)
	}
}

func TestVerify_RejectsWrongSigningKey(t *testing.T) {
	issA, _ := NewIssuer(validKey(), "agentgate", time.Minute)
	issB, _ := NewIssuer([]byte("ffffffffffffffffffffffffffffffff"), "agentgate", time.Minute)

	token, err := issA.Issue("agent-123", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := issB.Verify(token); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for wrong key, got %v", err)
	}
}

func TestVerify_RejectsGarbageToken(t *testing.T) {
	iss, _ := NewIssuer(validKey(), "agentgate", time.Minute)
	if _, err := iss.Verify("not-a-real-token"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for garbage input, got %v", err)
	}
}

func TestVerify_RejectsWrongIssuer(t *testing.T) {
	issA, _ := NewIssuer(validKey(), "agentgate-a", time.Minute)
	issB, _ := NewIssuer(validKey(), "agentgate-b", time.Minute)

	token, err := issA.Issue("agent-123", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := issB.Verify(token); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for mismatched issuer, got %v", err)
	}
}
