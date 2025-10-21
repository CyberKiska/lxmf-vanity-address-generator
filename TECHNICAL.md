# Technical Documentation

## Implementation Details

This document describes the technical implementation of the LXMF vanity address generator.

## Cryptographic Primitives

### Ed25519 Key Generation

Ed25519 is used for digital signatures in Reticulum identities.

**Process:**
1. Generate 32 random bytes as `seed` using `crypto/rand`
2. Compute `h = SHA-512(seed)`
3. Take first 32 bytes of `h` as `a_raw`
4. Apply clamping to `a_raw`:
   - `a_raw[0] &= 248` (0xF8) - clear 3 lowest bits
   - `a_raw[31] &= 127` (0x7F) - clear highest bit  
   - `a_raw[31] |= 64` (0x40) - set second-highest bit
5. Interpret clamped `a_raw` as scalar `a`
6. Compute public key: `A = a × B` (where B is Ed25519 base point)

**Storage:**
- Private: 32-byte `seed`
- Public: 32-byte `A` (point encoding)

### X25519 Key Generation

X25519 is used for Diffie-Hellman key exchange and encryption.

**Process:**
1. Generate 32 random bytes as `k_raw` using `crypto/rand`
2. Apply clamping directly to `k_raw`:
   - `k_raw[0] &= 248` (0xF8)
   - `k_raw[31] &= 127` (0x7F)
   - `k_raw[31] |= 64` (0x40)
3. Compute public key: `K = k × G` (where G is X25519 base point)

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

The LXMF destination address is computed using a **two-step hashing** process that matches `RNS.Destination.hash(identity, "lxmf", "delivery")`:

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
    // Check prefix (high nibbles of first N bytes)
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
    
    // Check postfix (low nibbles of last M bytes)
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

Each worker runs independently:
```go
for i := 0; i < workers; i++ {
    wg.Add(1)
    go worker(&wg, resultChan)
}
```

### Worker Loop

```go
func worker(wg *sync.WaitGroup, resultChan chan<- *Identity) {
    defer wg.Done()
    
    // Pre-allocate buffers (reused across iterations)
    var randBuf [64]byte
    destinationName := make([]byte, 77)
    
    for {
        // Check if another worker found result
        if atomic.LoadUint32(&found) == 1 {
            return
        }
        
        // Generate random keys
        rand.Read(randBuf[:])
        
        // Derive identity
        // ... (Ed25519 + X25519 generation)
        
        // Compute address
        hash := sha256.Sum256(destinationName)
        
        // Check pattern
        if matchesPattern(hash[:16]) {
            resultChan <- &identity
            return
        }
        
        atomic.AddUint64(&totalAttempts, 1)
    }
}
```

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

Human-readable hex encoding with all derived information:
```
LXMF Vanity Address Identity
============================

Address (LXMF): cafe61fa1df484eb57c3e37ef5928a3c
Identity Hash:  9f6813ed6789431163283575125249a8

Public Key (X25519 + Ed25519):
  X25519 Public:  <pub>
  Ed25519 Public: <pub>

Private Key (X25519 + Ed25519):
  X25519 Private: <private>
  Ed25519 Seed:   <seed>

--- Import formats ---
Base64 (MeshChat import string):
<b64>
Base32 (Sideband import string):
<b32>

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
./reticulum-vanity --prefix test --out my_identity

# Verify with Reticulum (requires: pip install rns)
rnid -i my_identity -H lxmf.delivery
```

The output hash should match the address in `my_identity.txt`.

## Security Considerations

### Randomness Source

Uses `crypto/rand` which provides:
- Cryptographically secure random numbers (CSPRNG)
- Platform-specific entropy sources:
  - Linux: `/dev/urandom`
  - macOS: `arc4random`
  - Windows: `CryptGenRandom`

### Key Clamping

Clamping ensures:
- Proper scalar range for curve operations
- Protection against timing attacks
- Conformance with RFC 7748 (X25519) and RFC 8032 (Ed25519)

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
