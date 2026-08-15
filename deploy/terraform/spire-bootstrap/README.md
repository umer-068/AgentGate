# spire-bootstrap (roadmap)

This module is a placeholder for the production identity upgrade described in
[`docs/adr/0001-go-over-rust-for-mvp.md`](../../../docs/adr/0001-go-over-rust-for-mvp.md):
replacing AgentGate's MVP HMAC-JWT issuer (`internal/identity`) with
SPIFFE/SPIRE-issued workload identity.

## Intended scope

- A SPIRE server (Deployment + Service) in its own namespace, backed by a
  Kubernetes `PersistentVolumeClaim` for the datastore.
- A SPIRE agent `DaemonSet` using the Kubernetes Workload Attestor, so pods
  are identified by their ServiceAccount / namespace / pod labels rather than
  a shared static secret.
- Registration entries binding the `agentgate` ServiceAccount to a SPIFFE ID
  such as `spiffe://<trust-domain>/ns/agentgate/sa/agentgate`.
- A `gateway.TokenVerifier` implementation in `internal/identity` that
  validates SPIFFE X.509-SVIDs or JWT-SVIDs instead of the HMAC-signed JWTs
  issued by `agentgate issue-token` today.

## Why this isn't built yet

Implementing this requires either a live Kubernetes cluster to validate
against or a much larger Terraform module than fits in the v1 scope. Rather
than ship an untested Terraform module, this directory documents the
intended shape so the next contributor has a concrete starting point instead
of a blank slate.

## Suggested first PR

1. `helm/spire` (from the upstream SPIFFE project) as a dependency, pinned.
2. A minimal `main.tf` that applies the chart plus one registration entry
   for the `agentgate` ServiceAccount.
3. A new `identity.SpiffeVerifier` implementing `gateway.TokenVerifier`,
   with the same test shape as `internal/identity/issuer_test.go`.
