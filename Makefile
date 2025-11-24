# Makefile for server-config

# Variables
BINARY_NAME=server-config
BUILD_DIR=build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

# Default target
.PHONY: all
all: clean test build

# Build for current platform
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) cmd/server-config/main.go

# Build for multiple platforms
.PHONY: build-all
build-all:
	@echo "Building $(BINARY_NAME) for multiple platforms..."
	@mkdir -p $(BUILD_DIR)

	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 cmd/server-config/main.go

	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 cmd/server-config/main.go

	# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 cmd/server-config/main.go

	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 cmd/server-config/main.go

	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe cmd/server-config/main.go

	@echo "All builds completed in $(BUILD_DIR)/"

# Install locally
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)

# Uninstall
.PHONY: uninstall
uninstall:
	@echo "Removing $(BINARY_NAME) from /usr/local/bin..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Lint code
.PHONY: lint
lint:
	@echo "Linting code..."
	golangci-lint run

# Vet code
.PHONY: vet
vet:
	@echo "Vetting code..."
	go vet ./...

# Tidy dependencies
.PHONY: tidy
tidy:
	@echo "Tidying dependencies..."
	go mod tidy

# Download dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	go mod download

# Generate documentation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	@mkdir -p docs/generated
	godoc -http=:6060 &
	@echo "Documentation available at http://localhost:6060"

# Create release artifacts
.PHONY: release
release: clean test build-all
	@echo "Creating release artifacts..."
	@mkdir -p releases/$(VERSION)

	# Create compressed archives
	cd $(BUILD_DIR) && \
	for binary in $(BINARY_NAME)-*; do \
		if [[ $$binary == *.exe ]]; then \
			zip -r ../releases/$(VERSION)/$${binary%.exe}.zip $$binary; \
		else \
			tar -czf ../releases/$(VERSION)/$$binary.tar.gz $$binary; \
		fi; \
	done

	# Create checksums
	cd releases/$(VERSION) && \
	sha256sum * > SHA256SUMS

	@echo "Release artifacts created in releases/$(VERSION)/"

# Development targets
.PHONY: dev
dev: build
	@echo "Running $(BINARY_NAME) in development mode..."
	sudo $(BUILD_DIR)/$(BINARY_NAME) --validate --verbose

# Quick build and run (for development)
.PHONY: run
run: build
	@echo "Building and running $(BINARY_NAME)..."
	sudo $(BUILD_DIR)/$(BINARY_NAME) $(ARGS)

# Show version
.PHONY: version
version:
	@echo "$(BINARY_NAME) version: $(VERSION)"

# Check for required tools
.PHONY: check-tools
check-tools:
	@echo "Checking for required development tools..."
	@command -v go >/dev/null 2>&1 || { echo "Go is required but not installed. Aborting." >&2; exit 1; }
	@command -v git >/dev/null 2>&1 || { echo "Git is required but not installed. Aborting." >&2; exit 1; }
	@echo "All required tools are installed."

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all          - Clean, test, and build"
	@echo "  build        - Build for current platform"
	@echo "  build-all    - Build for multiple platforms"
	@echo "  install      - Install to /usr/local/bin"
	@echo "  uninstall    - Remove from /usr/local/bin"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage report"
	@echo "  clean        - Clean build artifacts"
	@echo "  fmt          - Format code"
	@echo "  lint         - Lint code"
	@echo "  vet          - Vet code"
	@echo "  tidy         - Tidy dependencies"
	@echo "  deps         - Download dependencies"
	@echo "  docs         - Generate documentation"
	@echo "  release      - Create release artifacts"
	@echo "  dev          - Run in development mode"
	@echo "  run          - Build and run with ARGS"
	@echo "  version      - Show current version"
	@echo "  check-tools  - Check for required tools"
	@echo "  help         - Show this help message"

# Quick installation for development
.PHONY: install-dev
install-dev: build
	@echo "Installing $(BINARY_NAME) to ~/.local/bin..."
	@mkdir -p ~/.local/bin
	cp $(BUILD_DIR)/$(BINARY_NAME) ~/.local/bin/
	@echo "Make sure ~/.local/bin is in your PATH"
	@echo "Add this to your shell profile: export PATH=\"$$HOME/.local/bin:$$PATH\""
