.PHONY: lint gate build build-debug build-all clean test check fuzz smoke bench compatibility oracle regenerate-golden install deps help

BINARY ?= lxmf-vanity
PYTHON ?= python3
RNS_FLAGS ?=
BUILDFLAGS ?= -trimpath -buildvcs=false
BUILDMODE ?= -buildmode=pie
VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS ?= -s -w -buildid= -X main.version=$(VERSION)

# Build the binary
build:
	CGO_ENABLED=0 go build $(BUILDMODE) $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o "$(BINARY)" .

# Build with debug symbols
build-debug:
	go build -o "$(BINARY)-debug" .

TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

# One platform list drives builds and lint. Cleanup remains an explicit allow-list.
build-all:
	@set -eu; for target in $(TARGETS); do \
		suffix=""; if [ "$${target%/*}" = windows ]; then suffix=".exe"; fi; \
		CGO_ENABLED=0 GOOS=$${target%/*} GOARCH=$${target#*/} go build $(BUILDMODE) $(BUILDFLAGS) \
			-ldflags "$(LDFLAGS)" -o "lxmf-vanity-$${target%/*}-$${target#*/}$$suffix" .; \
	done

# Clean build artifacts
clean:
	rm -f -- lxmf-vanity lxmf-vanity-debug lxmf-vanity.exe \
		lxmf-vanity-linux-amd64 lxmf-vanity-linux-arm64 \
		lxmf-vanity-darwin-amd64 lxmf-vanity-darwin-arm64 \
		lxmf-vanity-windows-amd64.exe lxmf-vanity-windows-arm64.exe

# Run unit tests
test:
	go test ./...
	$(PYTHON) -m unittest discover -p '*_test.py'

# Run the full local Go validation suite
check:
	go test ./...
	go test -race ./...
	go vet ./...
	$(PYTHON) -m unittest discover -p '*_test.py'

# Run the native matcher fuzz target for a bounded interval
fuzz:
	go test -run '^$$' -fuzz '^FuzzAddressMatcher$$' -fuzztime=10s

# Run quick CLI smoke tests
smoke: build
	@echo "Testing with prefix 'ff'..."
	"./$(BINARY)" --prefix ff --dry-run
	@echo "\nTesting with postfix '99'..."
	"./$(BINARY)" --postfix 99 --dry-run
	@echo "\nTesting with both prefix 'a' and postfix 'b'..."
	"./$(BINARY)" --prefix a --postfix b --dry-run

# Run targeted benchmarks
bench:
	go test -run '^$$' -bench . -benchtime=5s

# End-to-end check using the installed RNS package
compatibility: build
	@set -eu; tmpdir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	"./$(BINARY)" --prefix 0 --workers 2 --out "$$tmpdir/identity"; \
	$(PYTHON) scripts/rns_compatibility_oracle.py --check testdata/rns-identity-vectors.json --binary "$(BINARY)" $(RNS_FLAGS); \
	$(PYTHON) verify.py "$$tmpdir/identity" $(RNS_FLAGS)

# Check or regenerate deterministic bytes using the installed reference.
oracle:
	$(PYTHON) scripts/rns_compatibility_oracle.py --check testdata/rns-identity-vectors.json $(RNS_FLAGS)

regenerate-golden:
	$(PYTHON) scripts/rns_compatibility_oracle.py --write testdata/rns-identity-vectors.json $(RNS_FLAGS)

# Install to system
install: build
	cp "$(BINARY)" /usr/local/bin/

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
	@echo "  clean      - Remove known build artifacts; preserve identities"
	@echo "  test       - Run unit tests"
	@echo "  check      - Run tests, race detector, and vet"
	@echo "  lint       - Check formatting, all target vets, and module hygiene"
	@echo "  gate       - Run lint, tests, race, fuzz, builds, FIPS, and reference compatibility"
	@echo "  fuzz       - Run the native address-matcher fuzz target"
	@echo "  smoke      - Run quick functionality tests"
	@echo "  bench      - Run targeted benchmarks"
	@echo "  compatibility - Generate and verify an identity with installed RNS"
	@echo "  oracle     - Check the deterministic corpus with installed RNS"
	@echo "  regenerate-golden - Regenerate deterministic RNS test vectors"
	@echo "  install    - Install to /usr/local/bin"
	@echo "  deps       - Download and tidy dependencies"
	@echo "  help       - Show this help message"

# Complete implementation gate. Reference packages must be installed for PYTHON.
lint:
	@test -z "$$(gofmt -s -l .)"
	go mod tidy -diff
	@set -eu; for target in $(TARGETS); do \
		CGO_ENABLED=0 GOOS=$${target%/*} GOARCH=$${target#*/} go vet ./...; \
	done

gate: lint test
	go test -race -count=1 ./...
	$(MAKE) fuzz
	$(MAKE) build build-all
	@set -eu; fips_log="$$(mktemp)"; trap 'rm -f -- "$$fips_log"' EXIT; \
	status=0; GODEBUG=fips140=only "./$(BINARY)" --prefix 0 --workers 1 --dry-run >"$$fips_log" 2>&1 || status=$$?; \
	test "$$status" -eq 1; grep -Fq 'X25519 public-key derivation unavailable' "$$fips_log"; \
	if grep -Eq 'panic:|fatal error:' "$$fips_log"; then cat "$$fips_log"; exit 1; fi
	$(MAKE) compatibility
