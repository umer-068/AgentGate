// Package config loads and validates AgentGate's runtime configuration from
// YAML, with environment-variable overrides for anything secret (signing
// keys, DSNs) so that no secret material needs to live in a config file
// checked into version control.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/goccy/go-yaml"
)

// Config is the top-level AgentGate configuration.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Identity IdentityConfig `yaml:"identity"`
	Policy   PolicyConfig   `yaml:"policy"`
	Audit    AuditConfig    `yaml:"audit"`
	Upstream UpstreamConfig `yaml:"upstream"`
}

// ServerConfig controls the HTTP listener.
type ServerConfig struct {
	Addr            string        `yaml:"addr"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// IdentityConfig controls short-lived agent session token issuance.
//
// This is an MVP stand-in for SPIFFE/SPIRE-issued workload identity (see
// docs/adr/0001-go-over-rust-for-mvp.md and the project roadmap): tokens are
// HMAC-signed JWTs with a short TTL, which is enough to demonstrate scoped,
// expiring credentials per agent session without standing up a full SPIRE
// server for local development.
type IdentityConfig struct {
	// SigningKeyEnv names the environment variable holding the HMAC signing
	// key. Never read directly from YAML.
	SigningKeyEnv string        `yaml:"signing_key_env"`
	TokenTTL      time.Duration `yaml:"token_ttl"`
	Issuer        string        `yaml:"issuer"`
}

// PolicyConfig points at the Rego policy bundle AgentGate evaluates every
// tool call against.
type PolicyConfig struct {
	BundlePath string `yaml:"bundle_path"`
	Query      string `yaml:"query"`
}

// AuditConfig controls where the immutable audit trail is written.
type AuditConfig struct {
	SQLitePath string `yaml:"sqlite_path"`
	// LogLevel controls the structured stdout logger (debug|info|warn|error).
	LogLevel string `yaml:"log_level"`
}

// UpstreamConfig maps logical tool names to the backend base URL AgentGate
// forwards allowed calls to.
type UpstreamConfig struct {
	Targets map[string]string `yaml:"targets"`
	Timeout time.Duration     `yaml:"timeout"`
}

// Load reads and validates configuration from the given YAML file path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: invalid: %w", err)
	}

	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Addr == "" {
		c.Server.Addr = ":8443"
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = 5 * time.Second
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = 10 * time.Second
	}
	if c.Server.ShutdownTimeout == 0 {
		c.Server.ShutdownTimeout = 10 * time.Second
	}
	if c.Identity.SigningKeyEnv == "" {
		c.Identity.SigningKeyEnv = "AGENTGATE_SIGNING_KEY"
	}
	if c.Identity.TokenTTL == 0 {
		c.Identity.TokenTTL = 15 * time.Minute
	}
	if c.Identity.Issuer == "" {
		c.Identity.Issuer = "agentgate"
	}
	if c.Policy.Query == "" {
		c.Policy.Query = "data.agentgate.authz.decision"
	}
	if c.Audit.LogLevel == "" {
		c.Audit.LogLevel = "info"
	}
	if c.Upstream.Timeout == 0 {
		c.Upstream.Timeout = 10 * time.Second
	}
}

func (c *Config) validate() error {
	if c.Policy.BundlePath == "" {
		return fmt.Errorf("policy.bundle_path is required")
	}
	if len(c.Upstream.Targets) == 0 {
		return fmt.Errorf("upstream.targets must declare at least one tool -> URL mapping")
	}
	switch c.Audit.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("audit.log_level must be one of debug|info|warn|error, got %q", c.Audit.LogLevel)
	}
	return nil
}

// SigningKey resolves the HMAC signing key from the environment variable
// named in IdentityConfig.SigningKeyEnv. Returns an error if unset, so a
// misconfigured deployment fails fast at startup instead of issuing
// predictably-signed tokens.
func (c *Config) SigningKey() ([]byte, error) {
	v := os.Getenv(c.Identity.SigningKeyEnv)
	if v == "" {
		return nil, fmt.Errorf("environment variable %s is not set", c.Identity.SigningKeyEnv)
	}
	if len(v) < 32 {
		return nil, fmt.Errorf("signing key in %s must be at least 32 bytes, got %d", c.Identity.SigningKeyEnv, len(v))
	}
	return []byte(v), nil
}
