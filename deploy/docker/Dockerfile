# syntax=docker/dockerfile:1

# --- build stage -------------------------------------------------------
# 1.26, not 1.24: Trivy flagged multiple stdlib CVEs (crypto/tls, net/http,
# encoding/xml, etc.) with no fix on the 1.24 branch - only 1.25.x/1.26.x.
# go.mod's own `go 1.24.7` directive is unaffected; a newer toolchain
# builds older-directive code fine (see docs/adr/0002 for the incident that
# led to this file getting a second look).
FROM golang:1.26-bookworm AS build

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# mattn/go-sqlite3 is cgo-based (see docs/adr/0001-go-over-rust-for-mvp.md),
# so CGO must stay enabled and gcc (present in the golang:*-bookworm image)
# is required for this build.
ENV CGO_ENABLED=1
RUN go build -trimpath -ldflags="-s -w" -o /out/agentgate ./cmd/agentgate

# --- runtime stage -------------------------------------------------------
# distroless/base (not /static) because the cgo binary links glibc.
FROM gcr.io/distroless/base-debian12:nonroot

WORKDIR /app
COPY --from=build /out/agentgate /app/agentgate
COPY config.example.yaml /app/config.yaml
COPY internal/policy/policies/policy.yaml /app/internal/policy/policies/policy.yaml

USER nonroot:nonroot
EXPOSE 8443

ENTRYPOINT ["/app/agentgate"]
CMD ["serve", "-config", "/app/config.yaml"]
