# Performance Guide

Every attempt includes fresh OS-backed entropy, X25519 and Ed25519 public-key
derivation, and LXMF hashing. Python is absent from the executable. Throughput
measurements must exercise this complete path.

## Measure locally

```bash
make build
./lxmf-vanity --benchmark 30s
./lxmf-vanity --benchmark 30s --workers 4
./lxmf-vanity --benchmark 30s --workers 8
make bench
```

Use the final average, calculated from measured monotonic elapsed time through
worker shutdown. The requested timeout is not assumed to be exact. Progress
rates also account for the actual interval between samples; counters are batched,
so short progress windows can fluctuate.

Record the CPU, OS, Go version, worker count, run duration, thermal/power state
and other workloads. Repeat runs without other CPU-heavy tasks. The default
`GOMAXPROCS` worker count is a useful starting point; extra workers are not
necessarily faster, especially on heterogeneous CPUs or in containers.

`--dry-run` stops at a match and discards its private key, making it unsuitable
for throughput comparisons. The CLI benchmark never selects or saves a winner.

## Search probability

For a total of `k` non-overlapping prefix/suffix hex characters, success
probability per attempt is `16^-k` and expected attempts are `16^k`.
For `--prefix ab --postfix cd`, probability is `1/65,536`; expected attempts
are `65,536`. A four-character prefix plus a four-character suffix requires
about 4.3 billion attempts on average.

| Total characters | Expected attempts | Expected time at an illustrative 45,000/s |
|---:|---:|---:|
| 4 | 65,536 | 1.5 seconds |
| 5 | 1,048,576 | 23 seconds |
| 6 | 16,777,216 | 6.2 minutes |
| 7 | 268,435,456 | 1.7 hours |
| 8 | 4,294,967,296 | 26.5 hours |

These are expectations, not deadlines or measured hardware promises. After any
number of unsuccessful attempts, the expected *additional* attempts remain
`16^k`. The probability of having found a match after `n` independent attempts is:

```text
P(found by n) = 1 - (1 - 16^-k)^n
```

Approximately three times the expected attempts gives a 95% success probability
for small per-attempt probabilities. Longer vanity patterns are not stronger
keys or stronger authentication.

## Implementation and measured costs

The matcher compares predecoded bytes/nibbles without allocating or rendering
hex strings. Workers reuse fixed candidate/hash buffers, precompute the LXMF
name hash and batch atomic counter updates. The standard curve operations
remain the dominant cost.

During the 8 September 2026 audit, isolated component benchmarks on Apple M1,
macOS/arm64, Go 1.27.0 gave these ranges (three one-second samples):

| Operation | Time per operation | Allocations |
|---|---:|---:|
| Candidate derivation, excluding entropy read | 53.29–53.69 µs | 192 bytes / 4 |
| X25519 public derivation | 36.68–36.70 µs | 192 bytes / 4 |
| Ed25519 public derivation | 16.09–18.60 µs | 0 |
| Successful matcher comparison | 7.08–7.10 ns | 0 |
| 64-byte secure random read | 0.260–0.263 µs | 0 |

Allocation ownership is toolchain-specific: in this measurement all four
allocations originated in X25519, not Ed25519. The checked-in
`BenchmarkSecureCandidate` includes the random read so future changes can be
compared against the real candidate path. `BenchmarkDeriveCandidate` and
`BenchmarkAddressMatcher` isolate the other boundaries.

The measured entropy cost here is roughly 0.5% of derivation time. That does
not justify adding secret-bearing entropy slabs or promising a batching speedup.
Linux and Windows entropy costs need native measurements before changing this
policy. Retain standard cryptographic APIs and independent fresh candidate
material; any optimization must show repeatable complete-path improvement and
pass the entire RNS corpus. Do not substitute a non-cryptographic generator,
reuse key halves, or introduce custom curves solely for benchmark speed.

## Build settings

Release builds use `CGO_ENABLED=0`, `-buildmode=pie`, `-trimpath`,
`-buildvcs=false`, and `-ldflags '-s -w -buildid='`. These control portability,
ASLR and embedded metadata; stripping symbols is not a curve-speed optimization.
CI records build information separately and attests trusted builds.

Use `make build-debug` for symbols. Private x86 builds may benchmark
`GOAMD64=v3 make build` if all target CPUs support it. Distributed binaries keep
the default architecture baseline. `make clean` only removes known binaries;
choose a separate directory for private identity output.
