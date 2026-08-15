// Package identity issues and verifies short-lived, scoped session tokens
// for AI agents connecting to AgentGate.
//
// Design note: production deployments of AgentGate are meant to sit behind
// SPIFFE/SPIRE for cryptographic workload identity (see the roadmap in
// docs/adr/0001-go-over-rust-for-mvp.md). This package is the MVP stand-in —
// HMAC-signed JWTs with a short TTL and an explicit scope claim — chosen so
// the gateway's authorization flow (issue -> verify -> scope-check) is fully
// exercised and testable without standing up an external identity plane for
// local development or CI.
package identity

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken is returned for any token that fails verification,
// deliberately without detail on *why* to avoid leaking signing internals to
// a caller probing the endpoint.
var ErrInvalidToken = errors.New("identity: invalid or expired token")

// Session describes the agent identity and permitted scope encoded in a
// token, as recovered after verification.
type Session struct {
	AgentID string   `json:"agent_id"`
	Scopes  []string `json:"scopes"`
}

type claims struct {
	Scopes []string `json:"scopes"`
	jwt.RegisteredClaims
}

// Issuer issues and verifies HMAC-signed session tokens.
type Issuer struct {
	signingKey []byte
	issuer     string
	ttl        time.Duration
	now        func() time.Time // overridable for tests
}

// NewIssuer builds an Issuer. signingKey must be at least 32 bytes; ttl must
// be positive.
func NewIssuer(signingKey []byte, issuerName string, ttl time.Duration) (*Issuer, error) {
	if len(signingKey) < 32 {
		return nil, fmt.Errorf("identity: signing key must be at least 32 bytes, got %d", len(signingKey))
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("identity: token ttl must be positive, got %s", ttl)
	}
	if issuerName == "" {
		return nil, fmt.Errorf("identity: issuer name must not be empty")
	}
	return &Issuer{
		signingKey: signingKey,
		issuer:     issuerName,
		ttl:        ttl,
		now:        time.Now,
	}, nil
}

// Issue mints a new short-lived token scoping agentID to the given scopes
// (e.g. []string{"tool:github:read"}).
func (i *Issuer) Issue(agentID string, scopes []string) (string, error) {
	if agentID == "" {
		return "", fmt.Errorf("identity: agentID must not be empty")
	}
	now := i.now()
	c := claims{
		Scopes: scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   agentID,
			Issuer:    i.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := token.SignedString(i.signingKey)
	if err != nil {
		return "", fmt.Errorf("identity: sign token: %w", err)
	}
	return signed, nil
}

// Verify checks signature, issuer, and expiry, returning the recovered
// Session on success.
func (i *Issuer) Verify(tokenString string) (*Session, error) {
	parsed, err := jwt.ParseWithClaims(tokenString, &claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return i.signingKey, nil
	}, jwt.WithIssuer(i.issuer), jwt.WithTimeFunc(i.now))
	if err != nil || !parsed.Valid {
		return nil, ErrInvalidToken
	}

	c, ok := parsed.Claims.(*claims)
	if !ok || c.Subject == "" {
		return nil, ErrInvalidToken
	}

	return &Session{AgentID: c.Subject, Scopes: c.Scopes}, nil
}
