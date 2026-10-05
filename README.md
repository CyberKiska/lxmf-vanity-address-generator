# LXMF Vanity Address Generator

A cross-platform, parallel Go CLI that generates Reticulum identities whose
`lxmf.delivery` destination has a chosen hexadecimal prefix and/or suffix.
The executable uses only the Go standard library. Python is used for optional
verification and reference tests, never in the search loop.

## Build and use

Go 1.26.8 or newer is required; Go 1.27.1 is the recommended release toolchain.

```bash
make build
identity_dir="$HOME/.lxmf-identities"
mkdir -m 700 "$identity_dir"
./lxmf-vanity --prefix cafe --out "$identity_dir/cafe"
./lxmf-vanity --prefix abc --postfix def --workers 4 --out "$identity_dir/abc-def"
```

Use a directory you control, outside the source checkout, shared folders and
automatically synchronized folders. Each output name must be new. Back up a successfully saved identity
securely before using it with Reticulum.

Patterns are case-insensitive hexadecimal, matched against the final
32-character destination address. Both conditions must match when supplied.
Their combined length cannot exceed 32. All arguments must be flags; unused
positional arguments are rejected before any output files are created.

| Option | Meaning |
|---|---|
| `--prefix <hex>` | Desired address prefix |
| `--postfix <hex>` | Desired address suffix |
| `--generator segmented\|independent` | Default segmented; independent redraws both halves for every candidate |
| `--workers <int>` | Parallel workers, 1–256; defaults to `GOMAXPROCS` |
| `--out <path>` | Private identity file; defaults to `identity` |
| `--fallback-out <path>` | Separately preflighted fallback file |
| `--save-retry-timeout <duration>` | Recovery deadline between I/O operations; 0 retries indefinitely |
| `--max-attempts <n>` | Exact reserved candidate cap; 0 is unlimited |
| `--timeout <duration>` | Search limit; a completed winner is still saved |
| `--dry-run` | Search until a match, then discard its private identity |
| `--benchmark <duration>` | Measure complete secure generation without saving; e.g. `30s` |
| `--include-private-exports` | Include reversible Base64/Base32 private exports in the sidecar |
| `--allow-inherited-windows-acl` | Explicitly accept an already secured Windows directory's inherited ACL |

At least one pattern is required outside benchmark mode. Search time is random:
`16^(prefix length + postfix length)` is the expected attempt count, not a
deadline. Use short patterns initially. `--dry-run` cannot produce a usable
identity because the private bytes are discarded; use `--benchmark` to measure
performance.

## Compatibility

The implementation matches Reticulum's identity and LXMF delivery construction:

```text
public_identity = X25519_public || Ed25519_public
identity_hash   = SHA256(public_identity)[:16]
name_hash       = SHA256(UTF8("lxmf.delivery"))[:10]
destination     = SHA256(name_hash || identity_hash)[:16]
private_file    = X25519_private[32] || Ed25519_seed[32]
```

The 64-byte private file loads directly with `RNS.Identity.from_file()` and
`rnid`. Newly generated X25519 private bytes use Reticulum's canonical scalar
mask. Existing imported encodings are never rewritten by the verifier.

The mandatory CI reference is RNS **1.5.2**, checked against the 131-vector
corpus and end-to-end tests with both PyCA and internal providers. They check
complete private/public bytes,
hashes, signatures, shared secrets, encryption round-trips, incoming SINGLE
LXMF destinations, and actual `rnid` file/Base64/Base32 imports. CI checks out
the exact reference commit.

Verification accepts other installed RNS versions when their tested behavior
matches. An optional version assertion is available for reproducible testing;
this is not a guarantee about untested future releases. Older RNS releases
are not part of the mandatory CI matrix.

## Output protection and recovery

Two files are produced:

1. `<out>`: the sensitive 64-byte private identity.
2. `<out>.txt`: public address, identity hash, public keys and full specifier.

The sidecar is public-only unless `--include-private-exports` is supplied.
With that option, **both files contain private identity material**. Base64 and
Base32 are reversible encodings, not encryption. Never commit private output;
ignore rules cannot cover arbitrary `--out` names. A short vanity prefix does
not authenticate a correspondent: compare the full destination address.

On Unix-like systems output files use mode `0600`. On Windows, mode bits do
not enforce a private ACL. Private output is refused by default: restrict the
output directory to your account using Windows security properties or `icacls`,
then pass `--allow-inherited-windows-acl`. This option acknowledges the inherited
ACL; it neither installs nor verifies one.

The program opens the parent directory before searching and uses that same
directory handle for writing and cleanup. Existing files, including dangling
symlinks, are never overwritten. A moved or replaced parent is reported, and
writes remain anchored to the original directory. The directory must still be
trusted; this does not protect against someone allowed to modify its contents.

Publication syncs a temporary file and prefers an atomic, no-replace hard link.
Filesystems without hard links use exclusive creation; that fallback is not
crash-atomic. Directory sync is best effort, so portable power-loss durability
is not guaranteed. Keep backups.

Every winner is re-derived and checked against the pattern before writing.
Completed temporary and published files are verified through protected, bounded
read-back. A verified recovery file is a saved identity. Written but unverified
files are reported separately. Repeated retries keep a bounded number of files.
A hard link is an alias of one inode; publication corruption is checked again
and a recovery copy is rebuilt from memory when necessary.

Recoverable save failures retry with delays of 1, 2, 4 seconds up to 30 seconds,
using the original directory handles. Configure `--fallback-out` before a long
search. `--save-retry-timeout` applies between operations and cannot interrupt a
blocked filesystem call. During recovery, two fresh Ctrl-C presses within ten
seconds abandon the in-memory winner; any retained files remain reported.
SIGTERM/SIGHUP do not confirm discard. Handled cancellation preserves an
in-flight completed match. SIGQUIT, SIGKILL, runtime-fatal entropy failures and
machine loss are outside this recovery guarantee.

Stdout contains the public result; banner, progress and notices use a bounded
stderr queue. Pipe progress uses plain lines once per minute. Saving never waits
for console writes. Owned private buffers are cleared before final output.
Exit statuses: 0 success; 1 no verified saved identity/runtime failure; 2 usage
error; 4 search limit without a match; 3 verified saved identity with deviations (including result delivery
failure); 130 cancellation or explicitly abandoned memory. Deviations include
recovery/fallback names, failed metadata, moved directories, retained files and
durability warnings. Inspect reported paths before retrying a search.

The default segmented generator draws 64 bytes at segment start, then a fresh
32-byte Ed25519 seed for each discarded candidate, replacing the X25519 half
after 65,536 candidates. Both independent secret inputs come from Go's
OS-backed `crypto/rand.Reader`. `--generator independent` redraws both halves
per candidate. This process emits at most one identity per segment; recovery
copies are the same identity. Segment count does not bound wall-clock exposure,
and cloned process/VM snapshots can duplicate state. Independent mode avoids
deliberate reuse but does not make snapshots safe.

Owned private buffers are cleared on handled returns, with no complete erasure
guarantee for compiler/runtime copies, opaque provider objects, swap or crashes.
RNS requires X25519, which is unavailable in Go's FIPS-only mode; startup returns
a normal unsupported-provider error. Known-answer checks exercise the standard
and segmented paths before searching; they are smoke checks, not proof of binary
integrity or entropy quality.

## Verification

Use a Python environment with Reticulum installed:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install rns -r requirements-reference.txt
.venv/bin/python verify.py "$identity_dir/cafe"
.venv/bin/rnid -i "$identity_dir/cafe" -H lxmf.delivery
```

On Windows the environment's executables are in `.venv\Scripts`.
`verify.py` requires exactly 64 private bytes, bounds metadata reads, checks
recognized metadata fields, and rejects conflicting/duplicate fields. It
reports the actual RNS version, provider and import path. Missing RNS or a
behavioral mismatch causes a nonzero exit.

```bash
# Optional CI assertion and provider selection:
.venv/bin/python verify.py "$identity_dir/cafe" --expect-rns-version 1.5.2 --provider pyca
# Explicit independent calculation without an RNS compatibility claim:
.venv/bin/python verify.py "$identity_dir/cafe" --manual-only
```

## Development and distribution

```bash
make test          # Go and Python tests
make check         # tests, race detector, vet
make fuzz          # bounded matcher fuzzing
make compatibility PYTHON=.venv/bin/python
make oracle PYTHON=.venv/bin/python RNS_FLAGS='--expect-rns-version 1.5.2 --provider internal'
make bench
make build-all     # Linux/macOS/Windows, amd64/arm64
make clean         # removes known build binaries; preserves identities
```

In **Actions → Build binaries → a successful run → Summary**, use the
**Download** links for Linux, macOS or Windows (amd64/arm64). The same six
bundles appear in the run's **Artifacts** section.

CI uses the single release Go toolchain for tests and builds; it does not
multiply jobs by historical Go or RNS versions. The two RNS providers run
sequentially in one compatibility job.

The release workflow gates six cgo-free PIE artifacts on platform tests,
reference tests, race/fuzz/FIPS checks and `govulncheck`. Artifacts include SHA-256
checksums and build information. Successful trusted `main` builds also receive
GitHub build-provenance attestations. Verify a downloaded binary with:

```bash
gh attestation verify ./lxmf-vanity-linux-amd64 --repo CyberKiska/lxmf-vanity-address-generator
```

Checksums detect corruption; provenance verification binds the binary to its
build. Pull-request artifacts are test builds and are not attested. Use the
workflow logs for validation results and `make bench` or `--benchmark` to measure
performance on your own hardware.

## License

GNU General Public License v3.0.

See [CHANGELOG.md](CHANGELOG.md) for changes and security fixes.
