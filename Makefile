.PHONY: build build-debug build-all clean test check smoke bench compatibility install deps help

BINARY ?= lxmf-vanity
BUILDFLAGS ?= -trimpath -buildvcs=false
LDFLAGS ?= -s -w -buildid=

# Build the binary
build:
	CGO_ENABLED=0 go build $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) .

# Build with debug symbols
build-debug:
	go build -o $(BINARY)-debug .

# Build for multiple platforms
build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o lxmf-vanity-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o lxmf-vanity-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o lxmf-vanity-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o lxmf-vanity-darwin-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o lxmf-vanity-windows-amd64.exe .
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o lxmf-vanity-windows-arm64.exe .

# Clean build artifacts
clean:
	rm -f lxmf-vanity lxmf-vanity-* identity identity.txt test_identity*

# Run unit tests
test:
	go test ./...
	python3 -m unittest verify_test.py

# Run the full local Go validation suite
check:
	go test ./...
	go test -race ./...
	go vet ./...
	python3 -m unittest verify_test.py

# Run quick CLI smoke tests
smoke: build
	@echo "Testing with prefix 'ff'..."
	./$(BINARY) --prefix ff --dry-run
	@echo "\nTesting with postfix '99'..."
	./$(BINARY) --postfix 99 --dry-run
	@echo "\nTesting with both prefix 'a' and postfix 'b'..."
	./$(BINARY) --prefix a --postfix b --dry-run

# Run targeted benchmarks
bench:
	go test -run '^$$' -bench . -benchtime=5s

# End-to-end check using the installed RNS package
compatibility: build
	@tmpdir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	./$(BINARY) --prefix 0 --workers 2 --out "$$tmpdir/identity"; \
	python3 verify.py "$$tmpdir/identity"

# Install to system
install: build
	cp $(BINARY) /usr/local/bin/

# Download dependencies
deps:
	go mod download
	go mod tidy

# Show help
help:
	@echo "Available targets:"
	@echo "  build      - Build the binary for current platform"
	@echo "  build-debug - Build a binary with debug symbols"
	@echo "  build-all  - Build binaries for all platforms"
	@echo "  clean      - Remove build artifacts and test files"
	@echo "  test       - Run unit tests"
	@echo "  check      - Run tests, race detector, and vet"
	@echo "  smoke      - Run quick functionality tests"
	@echo "  bench      - Run targeted benchmarks"
	@echo "  compatibility - Generate and verify an identity with installed RNS"
	@echo "  install    - Install to /usr/local/bin"
	@echo "  deps       - Download and tidy dependencies"
	@echo "  help       - Show this help message"
