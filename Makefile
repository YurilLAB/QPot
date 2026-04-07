# QPot Makefile

VERSION ?= 0.1.0
BINARY = qpot
MAIN_PACKAGE = ./cmd/qpot

# Build settings
LDFLAGS = -ldflags "-X main.version=$(VERSION) -X main.commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown) -X main.buildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)"

# Platforms
PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all build clean test install uninstall fmt vet lint docker

all: build

# Build for current platform
build:
	@echo "Building QPot $(VERSION)..."
	go build $(LDFLAGS) -o $(BINARY) $(MAIN_PACKAGE)
	@echo "✓ Built $(BINARY)"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BINARY)
	rm -rf dist/
	@echo "✓ Cleaned"

# Run tests
test:
	@echo "Running tests..."
	go test -v -race ./...
	@echo "✓ Tests passed"

# Format code
fmt:
	@echo "Formatting..."
	go fmt ./...
	@echo "✓ Formatted"

# Run go vet
vet:
	@echo "Running vet..."
	go vet ./...
	@echo "✓ Vet passed"

# Run linter
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "Running linter..."; \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping..."; \
	fi

# Install locally
install: build
	@echo "Installing..."
	mkdir -p $(HOME)/.local/bin
	cp $(BINARY) $(HOME)/.local/bin/
	@echo "✓ Installed to $(HOME)/.local/bin/$(BINARY)"

# Uninstall
uninstall:
	@echo "Uninstalling..."
	rm -f $(HOME)/.local/bin/$(BINARY)
	@echo "✓ Uninstalled"

# Build for all platforms
build-all:
	@echo "Building for all platforms..."
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		GOOS=$$(echo $$platform | cut -d/ -f1); \
		GOARCH=$$(echo $$platform | cut -d/ -f2); \
		OUTPUT="dist/$(BINARY)_$(VERSION)_$${GOOS}_$${GOARCH}"; \
		if [ "$$GOOS" = "windows" ]; then OUTPUT="$${OUTPUT}.exe"; fi; \
		echo "  Building for $$GOOS/$$GOARCH..."; \
		GOOS=$$GOOS GOARCH=$$GOARCH go build $(LDFLAGS) -o $$OUTPUT $(MAIN_PACKAGE); \
	done
	@echo "✓ Built all platforms"

# Create release archives
release: build-all
	@echo "Creating release archives..."
	@cd dist && for file in $(BINARY)_$(VERSION)_*; do \
		if echo "$$file" | grep -q "\.exe$$"; then \
			zip "$${file%.exe}.zip" "$$file"; \
		else \
			tar czf "$$file.tar.gz" "$$file"; \
		fi; \
	done
	@echo "✓ Created release archives"

# Run locally
dev: build
	@echo "Starting QPot in development mode..."
	./$(BINARY) up --instance dev

# Docker build
docker:
	@echo "Building Docker images..."
	docker build -t qpot/qpot:$(VERSION) -f docker/Dockerfile .
	@echo "✓ Built Docker image"

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy
	@echo "✓ Dependencies ready"

# Check for security vulnerabilities
security:
	@if command -v govulncheck >/dev/null 2>&1; then \
		echo "Checking for vulnerabilities..."; \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed, install with: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

# Generate code
generate:
	@echo "Generating code..."
	go generate ./...
	@echo "✓ Generated"

# Full CI check
ci: fmt vet lint test security
	@echo "✓ All CI checks passed"

# Help
help:
	@echo "QPot Makefile targets:"
	@echo ""
	@echo "  make build       - Build for current platform"
	@echo "  make build-all   - Build for all platforms"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make test        - Run tests"
	@echo "  make install     - Install locally"
	@echo "  make uninstall   - Uninstall"
	@echo "  make release     - Create release archives"
	@echo "  make docker      - Build Docker image"
	@echo "  make dev         - Run in development mode"
	@echo "  make ci          - Run all CI checks"
	@echo ""

.DEFAULT_GOAL := help
