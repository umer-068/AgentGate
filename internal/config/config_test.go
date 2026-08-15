package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

func TestLoad_AppliesDefaults(t *testing.T) {
	path := writeTempConfig(t, `
policy:
  bundle_path: ./policies
upstream:
  targets:
    github: https://api.github.com
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Server.Addr != ":8443" {
		t.Errorf("expected default addr :8443, got %q", cfg.Server.Addr)
	}
	if cfg.Identity.TokenTTL.String() != "15m0s" {
		t.Errorf("expected default token ttl 15m0s, got %s", cfg.Identity.TokenTTL)
	}
	if cfg.Policy.Query != "data.agentgate.authz.decision" {
		t.Errorf("unexpected default policy query: %s", cfg.Policy.Query)
	}
	if cfg.Audit.LogLevel != "info" {
		t.Errorf("expected default log level info, got %s", cfg.Audit.LogLevel)
	}
}

func TestLoad_MissingBundlePath(t *testing.T) {
	path := writeTempConfig(t, `
upstream:
  targets:
    github: https://api.github.com
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing policy.bundle_path, got nil")
	}
}

func TestLoad_MissingUpstreamTargets(t *testing.T) {
	path := writeTempConfig(t, `
policy:
  bundle_path: ./policies
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing upstream.targets, got nil")
	}
}

func TestLoad_InvalidLogLevel(t *testing.T) {
	path := writeTempConfig(t, `
policy:
  bundle_path: ./policies
upstream:
  targets:
    github: https://api.github.com
audit:
  log_level: verbose
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid log level, got nil")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	if _, err := Load("/nonexistent/path/config.yaml"); err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestSigningKey(t *testing.T) {
	cfg := &Config{Identity: IdentityConfig{SigningKeyEnv: "AGENTGATE_TEST_SIGNING_KEY"}}

	if _, err := cfg.SigningKey(); err == nil {
		t.Fatal("expected error when signing key env var is unset")
	}

	t.Setenv("AGENTGATE_TEST_SIGNING_KEY", "short")
	if _, err := cfg.SigningKey(); err == nil {
		t.Fatal("expected error when signing key is shorter than 32 bytes")
	}

	t.Setenv("AGENTGATE_TEST_SIGNING_KEY", "this-is-a-sufficiently-long-signing-key-value")
	key, err := cfg.SigningKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) == 0 {
		t.Fatal("expected non-empty signing key")
	}
}
