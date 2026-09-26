BINARY  := docker-trim
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG     := github.com/mkamranr/docker-trim/internal/version
LDFLAGS := -s -w -X $(PKG).version=$(VERSION) -X $(PKG).commit=$(COMMIT) -X $(PKG).date=$(DATE)

.PHONY: build test lint fmt bench integration clean install

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./...

# Golden files are reviewed line by line, never blindly accepted.
golden:
	go test ./... -update

lint:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt: files need formatting" >&2; exit 1)
	go vet ./...
	@# The ptrace collector only builds on linux, so check it there explicitly:
	@# on a developer's machine it is otherwise never compiled, and CI is a slow
	@# place to discover that.
	GOOS=linux GOARCH=amd64 go vet ./...
	GOOS=linux GOARCH=arm64 go vet ./...
	@if command -v golangci-lint >/dev/null; then \
		golangci-lint run --build-tags integration && \
		GOOS=linux GOARCH=amd64 golangci-lint run --build-tags integration; \
	else echo "golangci-lint not installed, skipped"; fi

fmt:
	gofmt -w .

bench:
	go test -bench=. -benchmem ./...

# Needs a running Docker daemon; builds real images.
integration: build
	DOCKER_TRIM_INTEGRATION=1 go test -tags integration -timeout 30m ./tests/... -v

install: build
	install -m 0755 $(BINARY) $${DOCKER_TRIM_BIN_DIR:-/usr/local/bin}/$(BINARY)

clean:
	rm -rf $(BINARY) dist tests/fixtures/generated
