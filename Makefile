.PHONY: build clean test install

# Build the binary
build:
	go build -o reticulum-vanity .

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o reticulum-vanity-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -o reticulum-vanity-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build -o reticulum-vanity-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -o reticulum-vanity-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -o reticulum-vanity-windows-amd64.exe .

# Clean build artifacts
clean:
	rm -f reticulum-vanity reticulum-vanity-* identity identity.txt test_identity*

# Run quick tests
test:
	@echo "Testing with prefix 'ff'..."
	./reticulum-vanity --prefix ff --dry-run
	@echo "\nTesting with postfix '99'..."
	./reticulum-vanity --postfix 99 --dry-run
	@echo "\nTesting with both prefix 'a' and postfix 'b'..."
	./reticulum-vanity --prefix a --postfix b --dry-run

# Install to system
install: build
	cp reticulum-vanity /usr/local/bin/

# Download dependencies
deps:
	go mod download
	go mod tidy

# Show help
help:
	@echo "Available targets:"
	@echo "  build      - Build the binary for current platform"
	@echo "  build-all  - Build binaries for all platforms"
	@echo "  clean      - Remove build artifacts and test files"
	@echo "  test       - Run quick functionality tests"
	@echo "  install    - Install to /usr/local/bin"
	@echo "  deps       - Download and tidy dependencies"
	@echo "  help       - Show this help message"

