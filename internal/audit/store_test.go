package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenStore_RejectsEmptyPath(t *testing.T) {
	if _, err := OpenStore(""); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestRecord_RejectsEmptyAgentID(t *testing.T) {
	s := newTestStore(t)
	err := s.Record(context.Background(), Entry{Tool: "github", Action: "read"})
	if err == nil {
		t.Fatal("expected error for empty AgentID")
	}
}

func TestRecordAndRecent_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	entries := []Entry{
		{AgentID: "agent-1", Tool: "github", Action: "read", Resource: "repo/a", Allowed: true, Reason: "scope match", PolicyID: "scope-allow"},
		{AgentID: "agent-1", Tool: "aws-s3", Action: "write", Resource: "prod-x", Allowed: false, Reason: "explicit deny", PolicyID: "explicit-deny"},
		{AgentID: "agent-2", Tool: "github", Action: "read", Resource: "repo/b", Allowed: true, Reason: "scope match", PolicyID: "scope-allow"},
	}
	for _, e := range entries {
		if err := s.Record(ctx, e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	agent1, err := s.Recent(ctx, "agent-1", 10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(agent1) != 2 {
		t.Fatalf("expected 2 entries for agent-1, got %d", len(agent1))
	}
	// Newest first.
	if agent1[0].Tool != "aws-s3" {
		t.Errorf("expected newest entry first (aws-s3), got %s", agent1[0].Tool)
	}
	if agent1[0].Timestamp.IsZero() {
		t.Error("expected non-zero timestamp on recorded entry")
	}

	all, err := s.Recent(ctx, "", 10)
	if err != nil {
		t.Fatalf("Recent (all): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 total entries, got %d", len(all))
	}
}

func TestRecord_DefaultsTimestamp(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	before := time.Now().UTC().Add(-time.Second)
	if err := s.Record(ctx, Entry{AgentID: "agent-1", Tool: "github", Action: "read"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	after := time.Now().UTC().Add(time.Second)

	entries, err := s.Recent(ctx, "agent-1", 1)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Timestamp.Before(before) || entries[0].Timestamp.After(after) {
		t.Errorf("timestamp %s not within expected window [%s, %s]", entries[0].Timestamp, before, after)
	}
}

func TestRecent_LimitDefaultsWhenNonPositive(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Record(ctx, Entry{AgentID: "agent-1", Tool: "github", Action: "read"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	entries, err := s.Recent(ctx, "agent-1", 0)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected default limit to still return the one entry, got %d", len(entries))
	}
}
