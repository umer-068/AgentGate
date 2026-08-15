package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3" // cgo-based SQLite driver
)

// Entry is one row of the immutable audit trail: a single policy decision
// made about a single tool call.
type Entry struct {
	ID        int64
	Timestamp time.Time
	AgentID   string
	Tool      string
	Action    string
	Resource  string
	Allowed   bool
	Reason    string
	PolicyID  string
}

// Store is an append-only SQLite-backed audit trail. Rows are never updated
// or deleted through this API by design — the audit log is only as
// trustworthy as its immutability.
type Store struct {
	db *sql.DB
}

// OpenStore opens (creating if necessary) the SQLite database at path and
// ensures the audit_log schema exists.
func OpenStore(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("audit: sqlite path must not be empty")
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("audit: open sqlite at %s: %w", path, err)
	}

	// SQLite handles one writer at a time; keeping this at 1 avoids
	// "database is locked" errors under concurrent gateway requests without
	// needing an external queue for an audit trail this size.
	db.SetMaxOpenConns(1)

	const schema = `
CREATE TABLE IF NOT EXISTS audit_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	agent_id TEXT NOT NULL,
	tool TEXT NOT NULL,
	action TEXT NOT NULL,
	resource TEXT NOT NULL,
	allowed INTEGER NOT NULL,
	reason TEXT NOT NULL,
	policy_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_agent_id ON audit_log(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: create schema: %w", err)
	}

	return &Store{db: db}, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// Record appends a decision entry to the audit trail. Timestamp is set to
// now if the zero value is passed.
func (s *Store) Record(ctx context.Context, e Entry) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.AgentID == "" {
		return fmt.Errorf("audit: entry.AgentID must not be empty")
	}

	const q = `
INSERT INTO audit_log (ts, agent_id, tool, action, resource, allowed, reason, policy_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`
	_, err := s.db.ExecContext(ctx, q,
		e.Timestamp.Format(time.RFC3339Nano),
		e.AgentID, e.Tool, e.Action, e.Resource,
		boolToInt(e.Allowed), e.Reason, e.PolicyID,
	)
	if err != nil {
		return fmt.Errorf("audit: record entry: %w", err)
	}
	return nil
}

// Recent returns the most recent audit entries for an agent, newest first,
// bounded by limit. Passing an empty agentID returns entries across all
// agents.
func (s *Store) Recent(ctx context.Context, agentID string, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 50
	}

	var rows *sql.Rows
	var err error
	if agentID == "" {
		rows, err = s.db.QueryContext(ctx, `
SELECT id, ts, agent_id, tool, action, resource, allowed, reason, policy_id
FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
SELECT id, ts, agent_id, tool, action, resource, allowed, reason, policy_id
FROM audit_log WHERE agent_id = ? ORDER BY id DESC LIMIT ?`, agentID, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("audit: query recent entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Entry
	for rows.Next() {
		var e Entry
		var ts string
		var allowedInt int
		if err := rows.Scan(&e.ID, &ts, &e.AgentID, &e.Tool, &e.Action, &e.Resource, &allowedInt, &e.Reason, &e.PolicyID); err != nil {
			return nil, fmt.Errorf("audit: scan row: %w", err)
		}
		parsed, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, fmt.Errorf("audit: parse timestamp: %w", err)
		}
		e.Timestamp = parsed
		e.Allowed = allowedInt != 0
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate rows: %w", err)
	}
	return out, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
