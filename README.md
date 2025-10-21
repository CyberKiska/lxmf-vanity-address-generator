# Reticulum LXMF Vanity Address Generator

A cross-platform multi-threaded CLI tool for generating vanity LXMF addresses in the Reticulum network with a specified prefix and/or suffix.

## Description

This tool generates LXMF identities with a specified pattern for the 16-byte address (32 hex characters). The address is calculated as a SHA-256 hash of the destination name, truncated to 128 bits.

Byte-for-byte compatible with the reference implementation of `RNS.Destination.hash()` for LXMF.

## Quick Start

```bash
# Build the project
make build

# Find an address starting with "cafe"
./lxmf-vanity --prefix cafe --out my_identity

# View the result
cat my_identity.txt
```

Done! Your identity is saved in files `my_identity` (binary) and `my_identity.txt` (text).

## Cryptography

- **Signing**: Ed25519 (`crypto/ed25519`)
- **Encryption/Key Exchange**: X25519 (`golang.org/x/crypto/curve25519`)
- **Hashing**: SHA-256 (`crypto/sha256`)
- **Random Source**: CSPRNG (`crypto/rand`)

## Installation

```bash
# Clone the repository
git clone https://github.com/CyberKiska/lxmf-vanity-address-generator
cd lxmf-vanity-address-generator

# Download dependencies
go mod download

# Build
go build -o lxmf-vanity .
```

## Usage

```bash
# Find an address with prefix "cafe"
./lxmf-vanity --prefix cafe --out my_identity

# Find an address with postfix (suffix) "1234"
./lxmf-vanity --postfix 1234 --out my_identity

# Find an address with prefix "abc" and postfix "def"
./lxmf-vanity --prefix abc --postfix def --out my_identity

# Use more threads for faster processing
./lxmf-vanity --prefix deadbeef --workers 16 --out my_identity

# Speed measurement mode (no saving)
./lxmf-vanity --prefix ff --dry-run
```

## Command Line Parameters

- `--prefix <hex>` - desired prefix at the beginning of the address (1-32 hex characters)
- `--postfix <hex>` - desired suffix at the end of the address (1-32 hex characters)
- `--workers <int>` - number of parallel threads (default = number of CPUs)
- `--out <path>` - path to save the identity file (default "identity")
- `--dry-run` - speed measurement mode only, no saving

## Output File Format

The program creates two files:

1. **`<out>`** - binary private key file (64 bytes):
   - X25519 private key (32 bytes)
   - Ed25519 seed (32 bytes)

   Format compatible with `RNS.Identity.to_file()` / `from_file()`

2. **`<out>.txt`** - text file with complete information:
   - LXMF address
   - Identity hash
   - Public keys (X25519 + Ed25519)
   - Private keys (X25519 + Ed25519)

## Verification

The project includes multiple verification scripts for different use cases:

### Unified Verification (Recommended)

The **`verify.py`** script combines the best of both worlds:

```bash
# Basic verification with .txt file comparison
python3 verify.py <identity_file>

# Install required dependencies
pip install cryptography rns

# The script will:
# ✅ Check file size (64 bytes)
# ✅ Compare with .txt file if available
# ✅ Verify cryptographic compatibility with Reticulum
# ✅ Show detailed results
```

### Manual Verification

For manual verification using Reticulum tools:

```bash
# Install Reticulum (Python)
pip install rns

# Verify the address (should match)
rnid -i <identity_file> -H lxmf.delivery
```

## How It Works

1. **X25519 Key Generation**:
   - Generate 32 bytes of random private key
   - Apply clamping: `[0] &= 248`, `[31] &= 127`, `[31] |= 64`
   - Public key = private × basepoint

2. **Ed25519 Key Generation**:
   - Generate 32 bytes of random seed
   - Compute SHA-512(seed), take first 32 bytes
   - Apply clamping (same operations)
   - Public key = scalar × basepoint

3. **Identity Public Key Formation**:
   - Concatenation: X25519.public (32) + Ed25519.public (32) = 64 bytes

4. **Identity Hash Calculation**:
   - Identity Hash = SHA-256(public_key)[0:16]

5. **LXMF Address Calculation** (double hashing):
   - Name Hash = SHA-256("lxmf.delivery")[0:10]
   - Addr Material = Name Hash (10) + Identity Hash (16) = 26 bytes
   - LXMF Address = SHA-256(Addr Material)[0:16]

6. **Parallel Search**:
   - Each worker generates keys in a loop
   - Checks if address matches prefix/suffix (without hex conversion)
   - When match found, stops others and saves result

## Complexity Estimation

Probability of finding an address with a given prefix:

- 1 hex character: ~16 attempts
- 2 characters: ~256 attempts
- 3 characters: ~4,096 attempts
- 4 characters: ~65,536 attempts
- 5 characters: ~1,048,576 attempts
- 6 characters: ~16,777,216 attempts
- 7 characters: ~268,435,456 attempts
- 8 characters: ~4,294,967,296 attempts

Speed depends on the processor. On modern CPUs, you can expect 100K-500K attempts/sec per core.

## Project Structure

```
.
├── main.go              # Main program code (+-390 lines)
├── go.mod / go.sum      # Go module and dependencies
├── Makefile             # Build and test commands
├── README.md            # Main documentation
├── TECHNICAL.md         # Technical documentation
├── PERFORMANCE.md       # Performance info
├── LICENSE              # GPLv3 license
├── verify.py            # Unified verification script
└── .gitignore           # Ignored files
```

## Additional Files

- **[TECHNICAL.md](TECHNICAL.md)** - detailed technical documentation for developers
- **[PERFORMANCE.md](PERFORMANCE.md)** - performance info and search time estimation
- **[verify.py](verify.py)** - python verification script

## Testing

```bash
# Run built-in tests
make test

# Check compatibility (requires Python)
./lxmf-vanity --prefix 7e57 --out test_id
python3 verify.py test_id
```

## Frequently Asked Questions

**Q: How long does it take to find an address with a long prefix?**
A: See [PERFORMANCE.md](PERFORMANCE.md) for time estimates.

**Q: Is it compatible with official Reticulum?**
A: Yes, compatible. Verify with `rnid -i <file> -H lxmf.delivery`. But if you want an implementation based on the reference RNS python implementation, check out the repository [lxmf-vanity-address-generator-py](https://github.com/CyberKiska/lxmf-vanity-address-generator-py).

**Q: Can I find an address with both prefix and suffix?**
A: Yes, use `--prefix` and `--postfix` simultaneously. Search time will increase.

## Acknowledgments

Created for the [Reticulum](https://github.com/markqvist/Reticulum) network - a self-organizing cryptography-based networking stack with readily available hardware.

## License

GNU General Public License v3.0
