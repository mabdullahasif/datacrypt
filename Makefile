# DataCrypt Makefile — Cross-platform build targets
# Usage: make [target]

BINARY_NAME := datacrypt
VERSION := 1.0.0
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ" 2>nul || echo unknown)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>nul || echo unknown)

LDFLAGS := -ldflags "-s -w \
	-X github.com/datacrypt/datacrypt/internal/cli.Version=$(VERSION) \
	-X github.com/datacrypt/datacrypt/internal/cli.BuildDate=$(BUILD_DATE) \
	-X github.com/datacrypt/datacrypt/internal/cli.GitCommit=$(GIT_COMMIT)"

GO := go
GOFLAGS := -trimpath

# Default target
.PHONY: all
all: build

# ============================================================================
# Build targets
# ============================================================================

.PHONY: build
build:
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME).exe ./cmd/datacrypt

.PHONY: build-linux
build-linux:
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 ./cmd/datacrypt
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME)-linux-arm64 ./cmd/datacrypt

.PHONY: build-macos
build-macos:
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 ./cmd/datacrypt
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME)-darwin-arm64 ./cmd/datacrypt

.PHONY: build-windows
build-windows:
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe ./cmd/datacrypt

.PHONY: build-all
build-all: build-linux build-macos build-windows

# ============================================================================
# Development targets
# ============================================================================

.PHONY: deps
deps:
	$(GO) mod download
	$(GO) mod tidy

.PHONY: test
test:
	$(GO) test -v -race -count=1 ./...

.PHONY: test-cover
test-cover:
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: fmt
fmt:
	$(GO) fmt ./...
	goimports -w .

# ============================================================================
# Cleanup
# ============================================================================

.PHONY: clean
clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe
	rm -f $(BINARY_NAME)-linux-* $(BINARY_NAME)-darwin-* $(BINARY_NAME)-windows-*
	rm -f coverage.out coverage.html

# ============================================================================
# Installation
# ============================================================================

.PHONY: install
install:
	$(GO) install $(GOFLAGS) $(LDFLAGS) ./cmd/datacrypt

.PHONY: help
help:
	@echo "DataCrypt Build System"
	@echo ""
	@echo "Targets:"
	@echo "  build          Build for current platform"
	@echo "  build-linux    Build for Linux (amd64 + arm64)"
	@echo "  build-macos    Build for macOS (amd64 + arm64)"
	@echo "  build-windows  Build for Windows (amd64)"
	@echo "  build-all      Build for all platforms"
	@echo "  deps           Download and tidy dependencies"
	@echo "  test           Run tests with race detector"
	@echo "  test-cover     Run tests with coverage report"
	@echo "  vet            Run go vet"
	@echo "  lint           Run golangci-lint"
	@echo "  fmt            Format source code"
	@echo "  clean          Remove build artifacts"
	@echo "  install        Install binary to GOPATH/bin"
	@echo "  help           Show this help"
