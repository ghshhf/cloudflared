# SkyNet sidecar — build, test, and lint targets
#
# This Makefile wraps common Go commands for the cloudflared sidecar.
# It does NOT require any non-Go tooling; only "go" is needed.

GO       ?= go
GOVET    ?= $(GO) vet
GOFMT    ?= $(GO) fmt
GOTEST   ?= $(GO) test
GOBUILD  ?= $(GO) build
GOCLEAN  ?= $(GO) clean -cache

# Default target
.PHONY: all
all: fmt vet build test

# ── Build ──────────────────────────────────────────────────────────────────

.PHONY: build
build:
	$(GOBUILD) -o skynet-tunnel$(SUFFIX) .

.PHONY: build-sidecar
build-sidecar:
	$(GOBUILD) -o cloudflared-sidecar$(SUFFIX) .

.PHONY: build-swbn
build-swbn:
	$(GOBUILD) -o swbn-pkg$(SUFFIX) ./cmd/swbn-pkg/

.PHONY: build-linux
build-linux:
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o skynet-tunnel-linux-amd64 .

.PHONY: build-darwin
build-darwin:
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o skynet-tunnel-darwin-amd64 .

.PHONY: build-windows
build-windows:
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o skynet-tunnel-windows-amd64.exe .

# ── Test ────────────────────────────────────────────────────────────────────

.PHONY: test
test:
	$(GOTEST) -count=1 -v ./...

.PHONY: test-short
test-short:
	$(GOTEST) -count=1 -short ./...

.PHONY: test-race
test-race:
	CGO_ENABLED=1 $(GOTEST) -count=1 -race ./...

.PHONY: test-coverage
test-coverage:
	$(GOTEST) -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

.PHONY: test-pkg
test-pkg:
	$(GOTEST) -count=1 -v ./$(PKG)

# ── Lint & Format ─────────────────────────────────────────────────────────

.PHONY: fmt
fmt:
	$(GOFMT) ./...

.PHONY: fmt-check
fmt-check:
	@if [ -n "$$($(GOFMT) -l ./...)" ]; then \
		echo "The following files need formatting:"; \
		$(GOFMT) -l ./...; \
		exit 1; \
	fi

.PHONY: vet
vet:
	$(GOVET) ./...

.PHONY: lint
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed; running go vet instead"; \
		$(GOVET) ./...; \
	fi

# ── Clean ──────────────────────────────────────────────────────────────────

.PHONY: clean
clean:
	$(GOCLEAN)
	rm -f skynet-tunnel skynet-tunnel-*
	rm -f cloudflared-sidecar cloudflared-sidecar-*
	rm -f swbn-pkg swbn-pkg-*
	rm -f coverage.out coverage.html

# ── Utilities ──────────────────────────────────────────────────────────────

.PHONY: count-lines
count-lines:
	@find . -name '*.go' -not -path './vendor/*' | xargs wc -l

.PHONY: count-tests
count-tests:
	@$(GOTEST) -count=1 ./... 2>&1 | grep -E '^(ok|FAIL)' | \
		awk '{print $$1, $$3, "("$$5}'

.PHONY: help
help:
	@echo "SkyNet sidecar Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all             fmt + vet + build + test (default)"
	@echo "  build           build sidecar (native OS/arch)"
	@echo "  build-linux     cross-compile for linux/amd64"
	@echo "  build-darwin    cross-compile for darwin/amd64"
	@echo "  build-windows   cross-compile for windows/amd64"
	@echo "  test            run all tests with verbose"
	@echo "  test-short      run tests with -short"
	@echo "  test-race       run tests with race detector (needs CGO)"
	@echo "  test-coverage   generate HTML coverage report"
	@echo "  fmt             run go fmt"
	@echo "  fmt-check       fail if any file needs formatting"
	@echo "  vet             run go vet"
	@echo "  lint            run golangci-lint (fallback: go vet)"
	@echo "  clean           remove build artifacts"
