// Package audit provides AgentGate's tamper-evident record of every
// decision the gateway makes: which agent, which tool call, what the policy
// engine decided, and why. Two sinks are maintained in parallel — structured
// stdout logs for real-time observability (ship to any log aggregator) and
// an append-only SQLite trail for after-the-fact investigation and the
// "what did this agent do in the last 24 hours" query.
package audit

import (
	"fmt"
	"log/slog"
	"os"
)

// NewLogger builds a JSON structured logger at the given level
// (debug|info|warn|error), writing to stdout so it composes cleanly with
// container log collection.
func NewLogger(level string) (*slog.Logger, error) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("audit: unknown log level %q", level)
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	return slog.New(handler), nil
}
