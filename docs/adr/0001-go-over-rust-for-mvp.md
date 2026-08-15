# ADR 0001: Go (not Rust) for the v1 gateway core, native policy evaluator (not OPA) for v1

**Status:** Accepted
**Date:** 2026-08

## Context

AgentGate's target production architecture (see the original project proposal) specifies a Rust gateway core, OPA/Rego for policy, and SPIFFE/SPIRE for workload identity — chosen for proxy performance, a real policy language, and cryptographic identity respectively.

Building the v1 MVP, two constraints changed the calculus:

1. **Velocity of a working, fully-tested v1 in a single build session** matters more than shaving proxy latency that isn't yet the bottleneck — there's no production traffic to optimize for yet, and a working, well-tested reference implementation is more valuable to reviewers (and more useful as a foundation) than an unfinished Rust core.
2. **The build environment has restricted network egress** — only direct git access to GitHub-hosted Go modules is reliably available; the Go module proxy (`proxy.golang.org`) and vanity-domain redirects (`gopkg.in/*`, `golang.org/x/*`, `modernc.org/*`) are blocked. The full `open-policy-agent/opa` Go module pulls in a very large transitive dependency graph (OpenTelemetry, gRPC, containerd, DNS mocking, `sigs.k8s.io/yaml`, etc.) for CLI and Wasm-runtime features AgentGate doesn't use, several of which sit behind blocked vanity domains with no viable `replace` directive.

## Decision

- **Gateway core: Go**, not Rust, for v1. `net/http` plus a small set of GitHub-hosted, dependency-light modules (`golang-jwt/jwt`, `goccy/go-yaml`, `mattn/go-sqlite3`) build cleanly offline and give a fully tested, production-shaped binary today.
- **Policy engine: a native Go evaluator** (`internal/policy`) implementing the identical deny-rule-then-scope-then-default-deny semantics the Rego reference policy expresses, rather than embedding `open-policy-agent/opa`. The Rego equivalent is checked in at `examples/policies/opa-reference/` as the documented production target.
- **Identity: HMAC-signed, short-lived JWTs** issued out-of-band by a CLI command (`agentgate issue-token`), rather than SPIFFE/SPIRE. This preserves the *shape* of the production design — short-lived, scoped, non-HTTP-issued credentials — without standing up an external identity plane for local development and CI.
- **Audit store: SQLite** via `mattn/go-sqlite3` (cgo, GitHub-hosted, no vanity-domain resolution needed), rather than `modernc.org/sqlite` (pure Go, but hosted on a blocked vanity domain in this environment) or ClickHouse (production target, but an unnecessary operational dependency for a single-node MVP).

Every one of these is wired behind a small interface in `internal/gateway` (`TokenVerifier`, `PolicyEngine`, `AuditRecorder`, `Forwarder`), so each swap is scoped to implementing one new interface and changing the constructor call in `cmd/agentgate/main.go` — no change to request-handling logic.

## Consequences

- **What we get today:** a fully buildable, fully tested (39 unit/integration tests across 5 packages), offline-buildable v1 that demonstrates the complete decision model (deny-override-scope-allow, audit-before-forward, non-HTTP token issuance) end to end.
- **What's deferred:** Rust's performance ceiling for the proxy hot path, Rego's expressiveness (rule composition, built-in test framework, bundle signing) for policy authors, and SPIFFE/SPIRE's cryptographic workload attestation and automatic rotation.
- **Re-evaluate when:** real request-volume data justifies a Rust rewrite of the hot path, or the deployment environment has unrestricted module/package registry access, making the OPA and SPIRE integrations a bounded-scope follow-up rather than a build-environment gamble.
