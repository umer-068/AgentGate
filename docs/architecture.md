# AgentGate — System Architecture

AgentGate is a zero-trust policy gateway that sits between AI agents (MCP clients, autonomous AIOps agents, coding assistants) and the infrastructure they're allowed to touch. It issues short-lived scoped credentials, enforces policy-as-code on every tool call, and records an immutable audit trail — before any call is forwarded, not after.

This document describes the system as built (v1 MVP): a single Go binary, a native policy evaluator, and a SQLite-backed audit trail, with the swap points to production-grade replacements (SPIFFE/SPIRE, OPA/Rego, ClickHouse) documented at each boundary. See [`docs/adr/0001-go-over-rust-for-mvp.md`](./adr/0001-go-over-rust-for-mvp.md) for why the MVP is scoped this way.

## Component architecture & data flow

```mermaid
flowchart TB
    subgraph operator["Operator / Platform Team"]
        CLI["agentgate issue-token CLI<br/>(out-of-band, never HTTP)"]
    end

    subgraph agent_side["AI Agent"]
        Agent["Agent / MCP Client<br/>(coding assistant, AIOps bot, etc.)"]
    end

    subgraph gw["AgentGate Gateway (single Go binary)"]
        direction TB
        HTTP["HTTP Server<br/>POST /v1/tool-call · GET /healthz"]
        Authn["Identity Verifier<br/>internal/identity<br/>(HMAC JWT · TTL-bound)"]
        Policy["Policy Engine<br/>internal/policy<br/>(deny-rules ⟶ scope-allow ⟶ default-deny)"]
        Audit["Audit Recorder<br/>internal/audit<br/>(structured JSON logs + SQLite)"]
        Fwd["HTTP Forwarder<br/>internal/gateway<br/>(per-tool upstream routing)"]

        HTTP --> Authn
        Authn -->|"session: agent_id + scopes"| Policy
        Policy -->|"decision (allow/deny + reason)"| Audit
        Audit -->|"if allowed"| Fwd
    end

    subgraph upstreams["Upstream Tools / Infra APIs"]
        GH["GitHub API"]
        S3["AWS S3"]
        K8s["Kubernetes API"]
        Other["... any tool in\nupstream.targets"]
    end

    subgraph store["Durable State"]
        SQLite[("SQLite audit_log<br/>append-only")]
        Bundle["policy.yaml<br/>(deny_rules)"]
        StdoutLogs["stdout JSON logs<br/>⟶ log aggregator"]
    end

    CLI -.->|"mints token for"| Agent
    Agent -->|"Bearer token + ToolCall JSON"| HTTP
    Fwd -->|"allowed calls only"| GH
    Fwd -->|"allowed calls only"| S3
    Fwd -->|"allowed calls only"| K8s
    Fwd -->|"allowed calls only"| Other
    Audit --> SQLite
    Audit --> StdoutLogs
    Policy -.->|"loads at startup"| Bundle

    style Policy fill:#2b6cb0,color:#fff
    style Audit fill:#c53030,color:#fff
    style Authn fill:#2f855a,color:#fff
```

### Request lifecycle (every call, no exceptions)

```mermaid
sequenceDiagram
    autonumber
    participant A as AI Agent
    participant G as AgentGate Gateway
    participant P as Policy Engine
    participant D as Audit Trail
    participant U as Upstream Tool API

    A->>G: POST /v1/tool-call (Bearer <session token>)
    G->>G: Verify JWT signature, issuer, expiry
    alt invalid or expired token
        G-->>A: 401 Unauthorized
    else valid session
        G->>P: Evaluate(tool, action, resource, scopes)
        P->>P: 1. Check deny_rules (org-wide ceiling)
        P->>P: 2. Check scope match (agent-level grant)
        P-->>G: Decision {allowed, reason, policy_id}
        G->>D: Record decision (SQLite + structured log)
        Note over D: Recorded BEFORE forwarding —<br/>a crash mid-call still leaves an audit trail
        alt denied
            G-->>A: 403 Forbidden {reason}
        else allowed
            G->>U: Forward call to upstream.targets[tool]
            U-->>G: Response
            G-->>A: 200 OK {decision, upstream response}
        end
    end
```

## Design principles that drove the layout

1. **Deny before allow, always audited.** The policy engine checks org-wide `deny_rules` first — no agent scope can override them. Every decision, allowed or denied, is written to the audit trail *before* any upstream call is attempted (`internal/gateway/gateway.go:audit`), so a mid-request crash never produces an unaudited action.
2. **Token issuance is not an HTTP endpoint.** Minting a session credential is a CLI/operator action (`cmd/agentgate issue-token`), never a route on the gateway itself — an unauthenticated "give me a token" endpoint would defeat the purpose of a zero-trust gateway. In production this responsibility moves to a SPIFFE/SPIRE workload attestor.
3. **Policy is data, not code.** `internal/policy` loads `policy.yaml` at startup; changing what agents can do means editing the bundle, not redeploying the binary. The interfaces in `internal/gateway` (`PolicyEngine`, `TokenVerifier`, `AuditRecorder`, `Forwarder`) are the seams where the native MVP evaluator, HMAC issuer, and SQLite store get swapped for OPA/Rego, SPIFFE/SPIRE, and ClickHouse respectively, with zero change to the gateway's request-handling logic.
4. **Every collaborator is an interface.** `Gateway` depends on four small interfaces rather than concrete types, which is what makes `internal/gateway/gateway_test.go` able to fully exercise the allow/deny/error paths with in-memory fakes and no real network, disk, or crypto in the unit test suite.

## Modular file/directory structure

```
agentgate/
├── cmd/
│   └── agentgate/
│       └── main.go              # CLI entrypoint: `serve` and `issue-token` subcommands
│
├── internal/                    # Not importable outside this module — the gateway's implementation
│   ├── config/
│   │   ├── config.go             # YAML config loading + validation + env-var secret resolution
│   │   └── config_test.go
│   │
│   ├── identity/
│   │   ├── issuer.go             # Short-lived HMAC-JWT session issuance & verification
│   │   └── issuer_test.go        # (MVP stand-in for SPIFFE/SPIRE workload identity)
│   │
│   ├── policy/
│   │   ├── engine.go             # Native Go deny-then-scope policy evaluator
│   │   ├── engine_test.go
│   │   └── policies/
│   │       └── policy.yaml       # The actual runtime policy bundle (deny_rules)
│   │
│   ├── audit/
│   │   ├── logger.go             # Structured JSON stdout logger (log/slog)
│   │   ├── store.go              # Append-only SQLite audit trail (mattn/go-sqlite3)
│   │   └── store_test.go
│   │
│   └── gateway/
│       ├── gateway.go            # HTTP handler wiring: authn → policy → audit → forward
│       ├── gateway_test.go       # Full request-lifecycle tests against fakes
│       ├── forwarder.go          # HTTPForwarder: relays allowed calls to upstream.targets
│       └── forwarder_test.go
│
├── pkg/
│   └── mcp/
│       └── types.go              # Public wire types: ToolCall, Decision, Result
│                                  # (importable by anyone building an AgentGate client)
│
├── examples/
│   └── policies/
│       └── opa-reference/        # The SAME policy expressed in real Rego — the
│           ├── agent_policy.rego #   production-upgrade reference once OPA is wired in
│           └── data.json
│
├── deploy/
│   ├── docker/
│   │   └── Dockerfile            # Multi-stage build → distroless runtime image
│   ├── helm/
│   │   └── agentgate/            # Minimal Helm chart (Deployment, Service, ConfigMap)
│   └── terraform/
│       └── spire-bootstrap/      # Roadmap module: bootstraps a SPIRE server + agent
│
├── docs/
│   ├── architecture.md           # This document
│   └── adr/
│       └── 0001-go-over-rust-for-mvp.md
│
├── .github/
│   └── workflows/
│       └── ci.yml                # build → vet → test → lint → Trivy image scan
│
├── config.example.yaml
├── go.mod / go.sum
├── Makefile
└── README.md
```

## Roadmap: swap points for the production hardening pass

| Component | MVP (v1) | Production target | Swap boundary |
|---|---|---|---|
| Workload identity | HMAC-signed JWT, CLI-issued | SPIFFE/SPIRE, auto-rotated | `identity.Issuer` / `gateway.TokenVerifier` |
| Policy engine | Native Go evaluator, YAML rules | OPA/Rego, bundle-signed | `policy.Engine` / `gateway.PolicyEngine` |
| Audit trail | SQLite, single-node | ClickHouse, real-time dashboard | `audit.Store` / `gateway.AuditRecorder` |
| Anomaly detection | none (roadmap) | Python isolation-forest sidecar on the audit stream | new consumer of `audit.Store` |
| Transport | plain HTTP (TLS via ingress) | mTLS via SPIRE-issued certs | `cmd/agentgate` server setup |

Each swap is scoped to one package because `internal/gateway` depends only on the four interfaces, never on concrete types — this is the same design decision that makes the current test suite fast and dependency-free.
