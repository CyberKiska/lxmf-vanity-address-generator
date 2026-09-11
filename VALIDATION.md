# Production hardening validation — 8 September 2026

This records the implementation checks following the audit of
`ceea7bcfae1d4b04ce938cb35b6939976778c206`. The cryptographic construction was
retained; no custom curves, candidate PRNG, reused key halves or Python search
runtime were introduced.

## Findings resolved

| Finding | Resolution |
|---|---|
| Cleanup deleted private identities | `make clean` names build artifacts explicitly; disposable-identity regression test |
| Verification rejected compatible RNS 1.5.2 | Behavior checks by default, optional exact-version assertion; both reference releases/providers exercised |
| Late file collisions discarded a winner | Primary collision retains complete recovery file; sidecar collision leaves primary saved |
| Positional arguments silently disabled later flags | CLI rejects unparsed arguments before preflight/search/output |
| Makefile hid compatibility-stage failures | Fail-fast recipe and injected failures at every stage |
| Metadata decoys satisfied substring checks | Exact recognized fields, duplicate rejection, canonical export checks and bounded reads |
| Parent paths could change during a search | Rooted directory handle held through preflight, publication and cleanup; replacement tests for both publication paths |
| Cancellation could discard an in-flight winner | Join workers, consume completed outcome, then report cancellation if no outcome exists |
| Benchmark averages assumed exact timeout | Measured elapsed time through worker shutdown; real interval progress rates |
| Assurance/distribution gaps | Expanded corpus, patched toolchains, vulnerability gates, pinned reference dependencies and main-build provenance |

## Executed locally

Host: Apple M1, macOS/arm64. Go 1.26.8 and 1.27.1. Python 3.14.7.
Reference dependency set: cryptography 50.0.1, pyserial 3.5, cffi 2.1.1,
pycparser 3.0. Only disposable generated identities and public fixture keys
were used.

| Check | Result |
|---|---|
| Full Go unit/CLI/corpus suite on minimum Go 1.26.8 | Passed |
| Full Go unit/CLI/corpus suite on release Go 1.27.1 | Passed |
| Go race detector | Passed |
| `go vet ./...` | Passed |
| Matcher fuzzing, 10 seconds, four workers | Passed, 1,067,803 executions; not a proof of complete coverage |
| Python tests, including without site packages | All 12 passed |
| RNS 1.4.2 × PyCA/internal | Both passed all 131 vectors and actual Go CLI/rnid checks |
| RNS 1.5.2 × PyCA/internal | Both passed all 131 vectors and actual Go CLI/rnid checks |
| Actual `make compatibility` with RNS 1.5.2/PyCA | Passed |
| Go FIPS-only CLI rejection | Exit 1 with X25519 provider error, no panic |
| cgo-free, stripped PIE builds | All six passed: Linux/macOS/Windows × amd64/arm64 |
| Go 1.27.1 source vulnerability scan | No known vulnerabilities found |
| Vulnerability scan of each of the six compiled binaries | No known vulnerabilities found |
| GitHub workflow syntax/expression validation | Passed actionlint 1.7.12 |

Vulnerability results are a snapshot of the live Go vulnerability database,
using govulncheck 1.8.0. They do not establish absence of undiscovered defects.
The workflow repeats source and binary scans before publishing artifacts.

## Performance evidence

Three two-second samples of `BenchmarkSecureCandidate` on Go 1.27.1 measured
53.52–53.88 µs per candidate, 192 bytes and four allocations per operation.
The matcher measured 7.08–7.20 ns, with no allocation. Five-second CLI samples
measured 17.49K/s with one worker, 59.08K/s with four, and 66.09K/s with eight.
These are local observations, not portable guarantees or controlled evidence
of a throughput improvement over the baseline.

The improvement is accurate measurement and reproducible coverage of the full
secure path. The audit found entropy reads too cheap on this Mac to justify
buffering changes; the standard curve APIs remain the measured bottleneck.
See [PERFORMANCE.md](PERFORMANCE.md) for interpretation and repeatable commands.

## Release boundary

Native Linux and Windows execution was not available on this host. Their unit
and CLI tests are configured in CI alongside native macOS tests, with both Go
toolchains. Cross-compilation does not substitute for those runtime checks.
The updated workflow has been statically validated, but this local work has
not pushed a branch, run GitHub CI, or generated a GitHub attestation. A successful
CI run is required before distributing its release artifacts.

No live LXMF network exchange or power-loss experiment was performed. The
compatibility scope is identity generation/serialization, delivery destination
derivation and reference cryptographic operations. Directory sync remains best
effort, exclusive fallback publication is not crash-atomic, and Windows output
requires a separately secured inherited ACL plus explicit acknowledgment.
Secret clearing is best effort under Go's memory model. These limits are
also documented in the user and technical guides.
