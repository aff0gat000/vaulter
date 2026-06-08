VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X github.com/aff0gat000/vaulter/cmd.Version=$(VERSION)"

.PHONY: build test cover integration integration-up integration-down lint clean docker docker-scan sast

build:
	go build -trimpath $(LDFLAGS) -o vaulter .

test:
	go test ./... -race -count=1

cover:
	go test ./... -race -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

integration:
	./test/integration/run.sh

# Start a local Vault (dev mode) seeded with dummy data and leave it running.
integration-up:
	./test/integration/dev.sh up

# Stop and remove the local dev Vault.
integration-down:
	./test/integration/dev.sh down

lint:
	go vet ./...
	@which staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipping"

sast:
	@which gosec >/dev/null 2>&1 && gosec ./... || echo "gosec not installed: go install github.com/securego/gosec/v2/cmd/gosec@latest"
	@which govulncheck >/dev/null 2>&1 && govulncheck ./... || echo "govulncheck not installed: go install golang.org/x/vuln/cmd/govulncheck@latest"

docker:
	docker build -t vaulter:$(VERSION) .

docker-scan:
	@which trivy >/dev/null 2>&1 && trivy image vaulter:$(VERSION) || echo "trivy not installed: see https://aquasecurity.github.io/trivy"

clean:
	rm -f vaulter coverage.out coverage.html
