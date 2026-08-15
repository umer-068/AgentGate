// Command agentgate runs the AgentGate zero-trust policy gateway, or (via
// the issue-token subcommand) mints short-lived session tokens for agents.
//
// Token issuance is deliberately a CLI/operator action, not an HTTP
// endpoint: an unauthenticated "give me a token" route would undermine the
// entire premise of the gateway. In a production deployment this
// subcommand's role is played by a SPIFFE/SPIRE workload attestor (see
// docs/adr/0001-go-over-rust-for-mvp.md) instead.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/naseerumer/agentgate/internal/audit"
	"github.com/naseerumer/agentgate/internal/config"
	"github.com/naseerumer/agentgate/internal/gateway"
	"github.com/naseerumer/agentgate/internal/identity"
	"github.com/naseerumer/agentgate/internal/policy"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agentgate:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agentgate <serve|issue-token> [flags]")
	}

	switch args[0] {
	case "serve":
		return runServe(args[1:])
	case "issue-token":
		return runIssueToken(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q (expected serve|issue-token)", args[0])
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to AgentGate config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger, err := audit.NewLogger(cfg.Audit.LogLevel)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}

	signingKey, err := cfg.SigningKey()
	if err != nil {
		return fmt.Errorf("resolve signing key: %w", err)
	}

	issuer, err := identity.NewIssuer(signingKey, cfg.Identity.Issuer, cfg.Identity.TokenTTL)
	if err != nil {
		return fmt.Errorf("init identity issuer: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	engine, err := policy.NewEngine(ctx, cfg.Policy.BundlePath, cfg.Policy.Query)
	if err != nil {
		return fmt.Errorf("init policy engine: %w", err)
	}

	auditStore, err := audit.OpenStore(cfg.Audit.SQLitePath)
	if err != nil {
		return fmt.Errorf("open audit store: %w", err)
	}
	defer func() {
		if err := auditStore.Close(); err != nil {
			logger.Error("failed to close audit store", "error", err)
		}
	}()

	forwarder, err := gateway.NewHTTPForwarder(cfg.Upstream.Targets, cfg.Upstream.Timeout)
	if err != nil {
		return fmt.Errorf("init forwarder: %w", err)
	}

	gw, err := gateway.New(issuer, engine, auditStore, forwarder, logger)
	if err != nil {
		return fmt.Errorf("init gateway: %w", err)
	}

	srv := &http.Server{
		Addr:         cfg.Server.Addr,
		Handler:      gw.Router(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("agentgate listening", "addr", cfg.Server.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func runIssueToken(args []string) error {
	fs := flag.NewFlagSet("issue-token", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to AgentGate config file")
	agentID := fs.String("agent", "", "agent ID to issue a session token for")
	scopesFlag := fs.String("scopes", "", "comma-separated scopes, e.g. tool:github:read,tool:aws-s3:read")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agentID == "" {
		return errors.New("issue-token: -agent is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	signingKey, err := cfg.SigningKey()
	if err != nil {
		return fmt.Errorf("resolve signing key: %w", err)
	}
	issuer, err := identity.NewIssuer(signingKey, cfg.Identity.Issuer, cfg.Identity.TokenTTL)
	if err != nil {
		return fmt.Errorf("init identity issuer: %w", err)
	}

	var scopes []string
	if *scopesFlag != "" {
		scopes = strings.Split(*scopesFlag, ",")
	}

	token, err := issuer.Issue(*agentID, scopes)
	if err != nil {
		return fmt.Errorf("issue token: %w", err)
	}

	fmt.Println(token)
	fmt.Fprintf(os.Stderr, "token issued for agent %q, expires in %s\n", *agentID, cfg.Identity.TokenTTL)
	return nil
}
