.PHONY: build build-debug build-all clean test check fuzz smoke bench compatibility oracle regenerate-golden install deps help

BINARY ?= lxmf-vanity
PYTHON ?= python3
BUILDFLAGS ?= -trimpath -buildvcs=false
BUILDMODE ?= -buildmode=pie
LDFLAGS ?= -s -w -buildid=

# Build the binary
build:
	CGO_ENABLED=0 go build $(BUILDMODE) $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) .

# Build with debug symbols
build-debug:
	go build -o $(BINARY)-debug .

# Build for multiple platforms
build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(BUILDMODE) $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o lxmf-vanity-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(BUILDMODE) $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o lxmf-vanity-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(BUILDMODE) $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o lxmf-vanity-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(BUILDMODE) $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o lxmf-vanity-darwin-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(BUILDMODE) $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o lxmf-vanity-windows-amd64.exe .
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(BUILDMODE) $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o lxmf-vanity-windows-arm64.exe .

# Clean build artifacts
clean:
	rm -f lxmf-vanity lxmf-vanity-* identity identity.txt test_identity*

# Run unit tests
test:
	go test ./...
	$(PYTHON) -m unittest verify_test.py

# Run the full local Go validation suite
check:
	go test ./...
	go test -race ./...
	go vet ./...
	$(PYTHON) -m unittest verify_test.py

# Run the native matcher fuzz target for a bounded interval
fuzz:
	go test -run '^$$' -fuzz '^FuzzAddressMatcher$$' -fuzztime=10s

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
	$(PYTHON) scripts/rns_compatibility_oracle.py --check testdata/rns-1.4.2-golden.json; \
	$(PYTHON) verify.py "$$tmpdir/identity"

# Check or regenerate the deterministic fixture using exactly RNS 1.4.2
oracle:
	$(PYTHON) scripts/rns_compatibility_oracle.py --check testdata/rns-1.4.2-golden.json

regenerate-golden:
	$(PYTHON) scripts/rns_compatibility_oracle.py --write testdata/rns-1.4.2-golden.json

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
	@echo "  fuzz       - Run the native address-matcher fuzz target"
	@echo "  smoke      - Run quick functionality tests"
	@echo "  bench      - Run targeted benchmarks"
	@echo "  compatibility - Generate and verify an identity with installed RNS"
	@echo "  oracle     - Check the deterministic fixture with RNS 1.4.2"
	@echo "  regenerate-golden - Regenerate the deterministic RNS 1.4.2 fixture"
	@echo "  install    - Install to /usr/local/bin"
	@echo "  deps       - Download and tidy dependencies"
	@echo "  help       - Show this help message"
