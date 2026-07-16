# LXMF Vanity Address Generator

A cross-platform, parallel Go CLI for generating Reticulum identities whose
`lxmf.delivery` destination hash has a chosen hexadecimal prefix and/or suffix.
Python is not used in the search loop.

## Compatibility

The implementation matches this Reticulum construction:

```text
public_identity = X25519_public || Ed25519_public
identity_hash   = SHA256(public_identity)[:16]
name_hash       = SHA256(UTF8("lxmf.delivery"))[:10]
destination     = SHA256(name_hash || identity_hash)[:16]
```

The saved private identity is the exact 64-byte layout consumed by
`RNS.Identity.from_file()`:

```text
X25519_private (32 bytes) || Ed25519_seed (32 bytes)
```

Compatibility is covered by an offline golden vector produced with Reticulum
1.3.8 at commit `de0f399a1696895dcb95ad1efa19f3b21a7886ab`. CI additionally generates an
identity and loads it through that pinned reference revision before publishing
cross-platform builds.

## Build and use

```bash
make build

./lxmf-vanity --prefix cafe --out my_identity
./lxmf-vanity --postfix 1234 --out my_identity
./lxmf-vanity --prefix abc --postfix def --out my_identity
./lxmf-vanity --prefix deadbeef --workers 8 --out my_identity
```

Patterns are case-insensitive hexadecimal and are matched against the final
32-character lowercase destination address. If both are supplied, both must
match. Their combined length must not exceed 32 characters.

### Options

- `--prefix <hex>`: desired address prefix.
- `--postfix <hex>`: desired address suffix.
- `--workers <int>`: parallel workers; defaults to `GOMAXPROCS` and is capped at 256.
- `--out <path>`: private identity path; defaults to `identity`.
- `--dry-run`: perform a real search and stop on a match without saving it.
- `--include-private-exports`: additionally put reversible Base64 and Base32 private identity exports in `<out>.txt`.

At least one pattern is required. Existing `<out>` or `<out>.txt` files are
never overwritten. The destination directory is write-tested before the
potentially long search starts.

## Output and security

By default two files are created:

1. `<out>` is the sensitive 64-byte Reticulum private identity.
2. `<out>.txt` contains public address, identity hash, public keys, and the full destination specifier.

The metadata file does **not** contain private keys by default. If
`--include-private-exports` is used, `<out>.txt` becomes a second private-key
file and must receive the same protection, backup policy, and retention policy
as `<out>`.

On Unix-like systems files are created with mode `0600`. On Windows, Go's Unix
mode bits do not establish an owner-only ACL; access is inherited from the
containing directory. Use a trusted private directory with an appropriate
Windows ACL.

Publication prefers a same-directory temporary file followed by atomic,
no-replace hard-link creation. On filesystems without hard-link support it
falls back to exclusive creation, which still refuses overwrite but cannot
offer the same crash-atomic publication guarantee.

## Verification

Install Reticulum and run:

```bash
python3 -m pip install cryptography rns
python3 verify.py my_identity
rnid -i my_identity -H lxmf.delivery
```

`verify.py` checks private-file round-trip, public keys, identity hash,
`RNS.Destination.hash()`, `hash_from_name_and_identity()`, and metadata. It
returns a non-zero status if RNS is unavailable; `--manual-only` must be used
explicitly for structural checks that do not establish reference compatibility.

## Development checks

```bash
make test          # unit and golden-vector tests
make check         # tests, race detector, and go vet
make compatibility # end-to-end check with the installed RNS package
make bench
make build-all
```

See [TECHNICAL.md](TECHNICAL.md) for protocol and implementation details and
[PERFORMANCE.md](PERFORMANCE.md) for probabilistic search-time guidance.

## License

GNU General Public License v3.0.
