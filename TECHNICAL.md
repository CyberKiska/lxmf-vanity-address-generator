# Technical Documentation

## Compatibility boundary

This program implements only the Reticulum behavior required to create and
persist an identity and derive its LXMF delivery destination. It is not a
general Reticulum implementation.

The executable protocol specification is pinned in tests to Reticulum 1.4.2,
commit `b48b96e61676504e0a4e527b33b9a0b4495c6872`. Future Reticulum revisions
must pass both the deterministic golden vector and the end-to-end CI check
before the supported reference revision is changed.

## Identity construction

Each candidate consumes 64 bytes from Go's `crypto/rand.Reader`:

```text
bytes  0..31: X25519 private input
bytes 32..63: Ed25519 seed
```

### X25519

Reticulum persists a 32-byte X25519 private key as the first half of its private
identity. The generator applies the RFC 7748 scalar mask before both deriving
the public key and retaining the private bytes:

```text
private[0]  &= 248
private[31] &= 127
private[31] |= 64
```

Go's standard `crypto/ecdh` X25519 implementation then derives the 32-byte
public u-coordinate. The explicit mask is intentionally retained because the
serialized private bytes, not just the public operation, are part of
compatibility. Fresh keys created by both RNS cryptographic providers use this
canonical masked representation. A separate RNS import subtlety is that loading
an externally supplied non-canonical X25519 encoding preserves those raw input
bytes when `get_private_key()` is called, even though scalar multiplication
masks them internally. This generator produces new identities; it does not
import or canonicalise existing identity files.

Go's FIPS 140-only mode rejects X25519 because it is not available through that
restricted provider. Candidate derivation propagates this as a normal error;
worker goroutines never panic on cryptographic-provider rejection.

### Ed25519

The second 32 bytes are an RFC 8032 Ed25519 seed. `ed25519.NewKeyFromSeed`
performs SHA-512 expansion, scalar pruning, and public-key derivation. Go's
returned 64-byte `seed || public` temporary is not persisted; only the seed is
stored in the identity file.

### Public and private ordering

Reticulum concatenates encryption material before signing material:

```text
public identity  = X25519_public  || Ed25519_public
private identity = X25519_private || Ed25519_seed
```

The identity hash is the first 16 bytes of SHA-256 over the complete 64-byte
public identity.

## LXMF destination derivation

For `RNS.Destination.hash(identity, "lxmf", "delivery")`, Reticulum does not
hash the printable full specifier directly. It first hashes the app/aspect name
without the printable identity suffix:

```text
name_hash       = SHA256(UTF8("lxmf.delivery"))[:10]
identity_hash   = SHA256(X25519_public || Ed25519_public)[:16]
hash_material   = name_hash || identity_hash
destination     = SHA256(hash_material)[:16]
```

`RNS.Destination.hash_from_name_and_identity("lxmf.delivery", identity)` splits
the name into the same app and aspect and delegates to this calculation.

## Pattern matching

The final destination is 16 bytes, rendered externally as 32 lowercase hex
characters. Patterns are decoded once:

- Complete prefix bytes compare from byte zero.
- An odd final prefix character compares the next byte's high nibble.
- Complete postfix bytes compare at the end of the address.
- An odd initial postfix character compares the preceding byte's low nibble.

Prefix and postfix conditions use logical AND. Individual lengths and combined
length are validated inside the matcher constructor, so bypassing CLI validation
cannot produce an out-of-range nibble access.

## Parallel search

The `searcher` owns immutable matcher state, a concurrency-safe CSPRNG reader,
and an atomic attempt counter. Each worker owns its candidate, entropy, public
key, and hash buffers.

A `sync.Once` guards a capacity-one outcome channel. The first matching
identity or entropy-source failure becomes the only outcome and cancels the
worker context. The result identity is sent by value. The main goroutine waits
for every worker before saving, so worker-local cleanup cannot mutate the
winner and only one save can occur.

SIGINT and SIGTERM cancel the same context. Entropy reads themselves are not
context-aware, so a worker already inside an operating-system random read can
only stop when that read returns.

`--benchmark` uses the identical entropy, X25519, Ed25519 and hashing path, but
disables match publication and stops on a deadline. It therefore cannot select
or accidentally discard a useful matching identity.

The default worker count is `runtime.GOMAXPROCS(0)`, which better reflects the
process CPU allowance than the host CPU count in constrained environments. The
CLI rejects counts outside 1..256.

## Persistence

The primary file is exactly 64 bytes:

| Offset | Size | Contents |
|---:|---:|---|
| 0 | 32 | masked X25519 private key |
| 32 | 32 | Ed25519 seed |

Targets are checked before the search and again immediately before saving.
`os.Lstat` is used so a dangling symlink is treated as an existing target.

Writes use a mode-`0600` same-directory temporary file, `fsync`, and hard-link
publication that cannot replace an existing target. If hard links are not
supported, an `O_CREATE|O_EXCL` fallback preserves the no-overwrite guarantee.
That fallback is not crash-atomic. Directory synchronization is best effort
because it is not uniformly supported across Go target platforms and filesystems.

The identity is committed before metadata. If metadata fails, the command
returns an error that explicitly states the identity was already saved; it does
not falsely report full bundle success.

If the identity temporary file is complete and synced but no-replace
publication fails because of a race or filesystem limitation, it is retained
at mode `0600` and the error reports its recovery path. Completed hard-link or
fallback publication removes the temporary entry before the final best-effort
directory sync, avoiding a second persistent link to secret material.

### Metadata policy

`<out>.txt` contains only public material by default. Reversible Base64 and
Base32 private exports require `--include-private-exports`, produce a prominent
warning, and make the metadata file sensitive.

Unix mode `0600` is not equivalent to a Windows ACL. The CLI fails closed for
private output on Windows unless the user explicitly passes
`--allow-inherited-windows-acl`, after restricting the output directory's
inherited ACL to the intended account.

## Secret lifetime

Worker entropy, candidate private fields, serialization buffers, and the
temporary Go Ed25519 private key receive best-effort clearing. Before any
identity is persisted, all public/hash/address fields are re-derived from the
private bytes and compared in constant time. `runtime.KeepAlive`
is used to retain the cleared object through the wipe point. Go does not promise
complete erasure: values can be copied by the runtime or compiler, and explicit
private export text necessarily exists in encoded form when that opt-in is used.

## Verification strategy

The Go test suite includes:

- A deterministic private/public/hash/address fixture from pinned RNS 1.4.2,
  reproducible with `scripts/rns_compatibility_oracle.py`.
- Odd/even and full-length matcher equivalence tests.
- A native Go fuzz target for matcher equivalence and panic resistance.
- Invalid-constructor tests.
- Concurrent winner, cancellation, and injected entropy-failure tests.
- Private-export opt-in, identity-consistency, permissions, symlink,
  no-overwrite, and recovery-publication tests.

CI additionally installs the pinned Reticulum revision, generates a real Go
identity, loads it with `RNS.Identity.from_file()`, and compares private
round-trip bytes, public keys, identity hash, both destination-hash APIs, and
metadata. It also exercises RNS signing, validation, encryption and decryption,
and rejects any installed RNS version other than 1.4.2. Unit tests run on Linux,
macOS and Windows, while race, fuzz and FIPS-error tests run on Linux.

`verify.py` fails closed when RNS is unavailable. `--manual-only` performs
structural calculations but deliberately does not claim reference compatibility.

## Performance invariants

Safe hot-loop properties are:

- Fixed worker-local buffers.
- Precomputed 10-byte LXMF name hash.
- `sha256.Sum256` without hash-object allocation.
- No address hex encoding in the loop.
- Predecoded byte/nibble matcher.
- Batched atomic attempt updates.

The dominant work is X25519 and Ed25519 public-key derivation. Optimizations
must preserve the exact private/public representations above. Custom curve
implementations, non-cryptographic candidate generators, or SHA-only shortcuts
are outside the acceptable security and compatibility boundary.

## References

- [Reticulum reference implementation](https://github.com/markqvist/Reticulum)
- [Reticulum API reference](https://reticulum.network/manual/reference.html)
- [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748)
- [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)
