# Technical Documentation

## Implementation Details

This document describes the technical implementation of the LXMF vanity address generator.

## Cryptographic Primitives

### Ed25519 Key Generation

Ed25519 is used for digital signatures in Reticulum identities.

**RFC 8032 (conceptual steps — what every conforming implementation does):**

1. Draw 32 random bytes; treat them as the private **seed** (what Reticulum stores as the second half of `Identity.get_private_key()`).
2. Hash the seed with SHA-512; clamp the first 32 bytes of that digest to form the secret scalar; multiply by the Ed25519 base point to obtain the public key `A`.

**This codebase:** the seed is generated with `crypto/rand`; the scalar expansion, clamping, and public-key derivation are **not** duplicated here — they are performed inside the Go standard library by `ed25519.NewKeyFromSeed`, which returns a 64-byte private key encoding (`seed || public`); the implementation copies out the 32-byte public half (`generateEd25519Public` in `main.go`). That matches RFC 8032 and is interoperable with PyCA / Reticulum’s `Ed25519PrivateKey` usage for the same 32-byte seed material.

**Storage:**

- Private on disk: 32-byte **seed** (second 32 bytes of the 64-byte identity file).
- Public: 32-byte compressed point `A`.

### X25519 Key Generation

X25519 is used for Diffie-Hellman key exchange and encryption.

**Process:**
1. Generate 32 random bytes as `k_raw` using `crypto/rand`
2. Apply clamping directly to `k_raw`:
   - `k_raw[0] &= 248` (0xF8)
   - `k_raw[31] &= 127` (0x7F)
   - `k_raw[31] |= 64` (0x40)
3. Compute public key: `K = k × G` (where G is the X25519 base point).

**This codebase:** the clamp from step 2 is implemented in `clampX25519`; the public key is `curve25519.ScalarBaseMult` (`golang.org/x/crypto/curve25519`), matching RFC 7748 and the same layout as Reticulum’s X25519 identity half.

**Storage:**
- Private: 32-byte clamped `k`
- Public: 32-byte `K` (u-coordinate)

## LXMF Address Computation

### Public Identifier Format

The public identifier is a 64-byte concatenation:
```
[X25519.public (32 bytes)] + [Ed25519.public (32 bytes)]
```

### Destination Hash Computation (LXMF)

The LXMF destination address matches `RNS.Destination.hash(identity, "lxmf", "delivery")` in the reference implementation. The Reticulum manual states that single destinations logically include the public key in the name; in code, the **name hash** is still taken over the **human/app string only** — `expand_name(None, "lxmf", "delivery")` → `"lxmf.delivery"` (UTF-8) — and the **identity hash** (truncated hash of the 64-byte public key) is concatenated **before** the outer SHA-256, exactly as below.

**Step 1: Compute Name Hash**
```
name = "lxmf.delivery"
name_hash = SHA-256(name)[:10]  # First 80 bits (10 bytes)
```

**Step 2: Compute Identity Hash**
```
public_key = X25519.pub (32) + Ed25519.pub (32)
identity_hash = SHA-256(public_key)[:16]  # First 128 bits (16 bytes)
```

**Step 3: Compute Destination Hash**
```
addr_hash_material = name_hash + identity_hash  # 10 + 16 = 26 bytes
destination_hash = SHA-256(addr_hash_material)[:16]  # First 128 bits
```

This is the **LXMF address** (16 bytes / 32 hex characters).

**Code:**
```go
// Step 1: Compute name hash (done once, reused)
nameHashFull := sha256.Sum256([]byte("lxmf.delivery"))
nameHash := nameHashFull[:10]

// Step 2: Build public key and compute identity hash
var publicKey [64]byte
copy(publicKey[0:32], identity.X25519Public[:])
copy(publicKey[32:64], identity.Ed25519Public[:])

identityHashFull := sha256.Sum256(publicKey[:])
copy(identity.Hash[:], identityHashFull[:16])

// Step 3: Compute destination hash
var addrHashMaterial [26]byte
copy(addrHashMaterial[0:10], nameHash)
copy(addrHashMaterial[10:26], identity.Hash[:])

addrHashFull := sha256.Sum256(addrHashMaterial[:])
copy(identity.Address[:], addrHashFull[:16])
```

## Pattern Matching

### Hex Encoding

Addresses are compared in hexadecimal:
- 16 bytes = 32 hex characters
- Lowercase format: `0-9a-f`

### Matching Algorithm

The pattern matching uses **direct nibble comparison** without hex encoding to avoid string allocations in the hot loop:

```go
func matchesPattern(addr []byte) bool {
    // Check prefix (first N nibbles of the address, high or low per position)
    if len(prefixNibbles) > 0 {
        for i := 0; i < len(prefixNibbles); i++ {
            byteIdx := i / 2
            nibble := byte(0)
            if i%2 == 0 {
                nibble = (addr[byteIdx] >> 4) & 0x0F  // High nibble
            } else {
                nibble = addr[byteIdx] & 0x0F         // Low nibble
            }
            if nibble != prefixNibbles[i] {
                return false
            }
        }
    }
    
    // Check postfix (last M nibbles of the address, high or low per position)
    if len(postfixNibbles) > 0 {
        addrLen := len(addr) * 2
        startNibble := addrLen - len(postfixNibbles)
        
        for i := 0; i < len(postfixNibbles); i++ {
            nibbleIdx := startNibble + i
            byteIdx := nibbleIdx / 2
            nibble := byte(0)
            if nibbleIdx%2 == 0 {
                nibble = (addr[byteIdx] >> 4) & 0x0F
            } else {
                nibble = addr[byteIdx] & 0x0F
            }
            if nibble != postfixNibbles[i] {
                return false
            }
        }
    }
    
    return true
}
```

## Multi-Threading Architecture

### Worker Pool

The main goroutine starts one worker per CPU (or `--workers`), plus a progress monitor. Each worker shares `resultChan`, `errChan`, and atomic flags with the same signature as in `main.go`:

```go
for i := 0; i < workers; i++ {
    wg.Add(1)
    go worker(&wg, resultChan, errChan)
}
```

### Worker Loop

Each iteration draws **64** CSPRNG bytes: first 32 for the X25519 scalar (then RFC 7748 clamp + `curve25519.ScalarBaseMult`), second 32 for the Ed25519 **seed** (`ed25519.NewKeyFromSeed`). The LXMF address is the **three-step** hash from [LXMF Address Computation](#lxmf-address-computation) (not a single hash of a long “destination name” buffer). Pseudocode aligned with `worker` in `main.go`:

```go
func worker(wg *sync.WaitGroup, resultChan chan<- *Identity, errChan chan<- error) {
    defer wg.Done()

    var randBuf [64]byte
    nameHashFull := sha256.Sum256([]byte("lxmf.delivery"))
    nameHash := nameHashFull[:10] // reused every iteration (same as RNS name_hash input)

    for {
        if atomic.LoadUint32(&found) == 1 {
            return
        }
        if _, err := rand.Read(randBuf[:]); err != nil {
            // on failure: CAS found, non-blocking send to errChan, return
            return
        }

        var identity Identity
        copy(identity.X25519Private[:], randBuf[0:32])
        copy(identity.Ed25519Seed[:], randBuf[32:64])
        clampX25519(&identity.X25519Private)
        curve25519.ScalarBaseMult(&identity.X25519Public, &identity.X25519Private)
        generateEd25519Public(&identity)

        var publicKey [64]byte
        copy(publicKey[0:32], identity.X25519Public[:])
        copy(publicKey[32:64], identity.Ed25519Public[:])
        identityHashFull := sha256.Sum256(publicKey[:])
        copy(identity.Hash[:], identityHashFull[:16])

        var addrHashMaterial [26]byte
        copy(addrHashMaterial[0:10], nameHash)
        copy(addrHashMaterial[10:26], identity.Hash[:])
        addrHashFull := sha256.Sum256(addrHashMaterial[:])
        copy(identity.Address[:], addrHashFull[:16])

        atomic.AddUint64(&totalAttempts, 1)
        if matchesPattern(identity.Address[:]) {
            if atomic.CompareAndSwapUint32(&found, 0, 1) {
                resultChan <- &identity
            }
            return
        }
    }
}
```

`totalAttempts` is incremented **after** computing the candidate address (same ordering as production code).

### Synchronization

- **Atomic counters:** `totalAttempts` and `found` use `sync/atomic`
- **Result channel:** First worker to find match sends result
- **Graceful shutdown:** Workers check `found` flag and exit

### Performance Monitoring

Separate goroutine tracks progress:
```go
func monitorProgress() {
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()
    
    lastAttempts := uint64(0)
    
    for {
        <-ticker.C
        if atomic.LoadUint32(&found) == 1 {
            return
        }
        
        current := atomic.LoadUint64(&totalAttempts)
        rate := current - lastAttempts
        fmt.Printf("\r  Speed: %d/s | Total: %d", rate, current)
        lastAttempts = current
    }
}
```

## Identity File Format

### Binary Format (64 bytes)

The identity file stores only the **private key** in the same format as `RNS.Identity.get_private_key()`:

```
Offset | Size | Content
-------|------|------------------
0      | 32   | X25519 private key
32     | 32   | Ed25519 seed
```

**Total:** 64 bytes

This matches the format produced by `RNS.Identity.to_file()` and can be loaded with `RNS.Identity.from_file()`.

### Text Format (.txt)

Human-readable metadata plus optional import encodings of the same private identity bytes:
```
LXMF Vanity Address Identity
============================

Address (LXMF): cafe61fa1df484eb57c3e37ef5928a3c
Identity Hash:  9f6813ed6789431163283575125249a8
Full Specifier: lxmf.delivery.9f6813ed6789431163283575125249a8:cafe61fa1df484eb57c3e37ef5928a3c

Public Key (X25519 + Ed25519):
  X25519 Public:  <pub>
  Ed25519 Public: <pub>
  Combined:       <pub>

Import formats for the same private identity bytes (keep this file secret):
  Base64 (MeshChat / Reticulum urlsafe):
  <b64url>
  Base32 (Sideband / Reticulum):
  <b32>

Reticulum-compatible private key material is also stored in:
  <out>

Verify with:
  rnid -i <out> -H lxmf.delivery

```

## Compatibility with Reticulum

### Reference Implementation

Reticulum (Python) uses:
- `cryptography` library for Ed25519/X25519
- `hashlib.sha256()` for hashing
- Specific byte order for public identifier

### Verification

To verify compatibility:
```bash
# Generate identity
./lxmf-vanity --prefix test --out my_identity

# Verify with Reticulum (requires: pip install rns)
rnid -i my_identity -H lxmf.delivery
```

The output hash should match the address in `my_identity.txt`.

## Security Considerations

### Randomness Source

Uses `crypto/rand` which provides:
- Cryptographically secure random numbers from the host platform CSPRNG through Go's standard library
- No fallback to a non-cryptographic PRNG in the hot loop

### Key Clamping

- **X25519:** this tool applies RFC 7748 clamping to the random 32-byte scalar in `clampX25519`, then `curve25519.ScalarBaseMult` — same curve role as in Reticulum’s `Identity` X25519 key.
- **Ed25519:** clamping of the expanded secret scalar is **inside** `crypto/ed25519` when deriving the key from the seed; see [Ed25519 Key Generation](#ed25519-key-generation).

### Hash Truncation

Truncating SHA-256 to 128 bits:
- Maintains collision resistance (2^64 operations)
- Standard practice for hash-based identifiers
- Sufficient for network address space

## Performance Characteristics

### Time Complexity

Per iteration:
- Random generation: O(1)
- SHA-512 (Ed25519): O(1)
- Point multiplication: O(log n) - ~10-20 operations
- SHA-256 (address): O(1)
- Pattern check: O(k) where k = pattern length

**Total:** ~20-30 microseconds per iteration on modern CPU

### Space Complexity

Per worker:
- Stack: ~1-2 KB
- Heap: ~100 bytes (pre-allocated buffers)

Total memory: ~workers × 2 KB ≈ 16 KB for 8 workers

### CPU Utilization

- Near 100% on all worker cores
- No I/O bottleneck
- Minimal memory bandwidth usage
- Cache-friendly (small working set)

## Future Optimizations

### 1. SIMD SHA-256

Use platform-specific SIMD instructions:
- AVX2 on x86
- NEON on ARM
- Potential 2-4× speedup

### 2. GPU Acceleration

Implement on CUDA/OpenCL:
- Potential 100-1000× speedup
- Good for very long patterns (8+ chars)

### 3. Distributed Computing

Network protocol for coordinating multiple machines:
- Linear scaling with number of machines
- Requires collision prevention strategy

## References

- [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) - X25519
- [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) - Ed25519
- [Reticulum Documentation](https://reticulum.network/manual/)
- [Go crypto packages](https://pkg.go.dev/crypto)
