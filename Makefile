.PHONY: build test lint vet run issue-token docker-build helm-lint clean

BINARY := agentgate
GOFLAGS_ENV := CGO_ENABLED=1

build:
	$(GOFLAGS_ENV) go build -trimpath -ldflags="-s -w" -o bin/$(BINARY) ./cmd/agentgate

test:
	$(GOFLAGS_ENV) go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1

vet:
	go vet ./...

lint:
	golangci-lint run ./...

run: build
	AGENTGATE_SIGNING_KEY=$${AGENTGATE_SIGNING_KEY:-dev-only-signing-key-please-rotate-me!} \
		./bin/$(BINARY) serve -config config.example.yaml

issue-token: build
	AGENTGATE_SIGNING_KEY=$${AGENTGATE_SIGNING_KEY:-dev-only-signing-key-please-rotate-me!} \
		./bin/$(BINARY) issue-token -config config.example.yaml -agent demo-agent -scopes "tool:github:read"

docker-build:
	docker build -f deploy/docker/Dockerfile -t agentgate:local .

helm-lint:
	helm lint deploy/helm/agentgate

clean:
	rm -rf bin coverage.out agentgate-audit.db
