# Performance Guide

## Expected Search Times

The time to find a vanity address depends on the pattern complexity and your measured local throughput. The current implementation performs full identity generation for every attempt: CSPRNG input, X25519 public key derivation, Ed25519 public key derivation, and LXMF destination hashing. It is not a SHA-only benchmark.

### Probability and Expected Attempts

Each hex character adds a factor of 16 to the search space:

| Pattern Length | Probability | Expected Attempts | Approx. Time at 45K/s | Approx. Time at 165K/s |
|----------------|-------------|-------------------|------------------------|-------------------------|
| 1 character    | 1/16        | ~16               | < 1 second             | < 1 second              |
| 2 characters   | 1/256       | ~256              | < 1 second             | < 1 second              |
| 3 characters   | 1/4,096     | ~4,096            | < 1 second             | < 1 second              |
| 4 characters   | 1/65,536    | ~65,536           | ~1.5 seconds           | < 1 second              |
| 5 characters   | 1/1,048,576 | ~1,048,576        | ~23 seconds            | ~6 seconds              |
| 6 characters   | 1/16,777,216| ~16,777,216       | ~6 minutes             | ~2 minutes              |
| 7 characters   | 1/268M      | ~268,435,456      | ~1.7 hours             | ~27 minutes             |
| 8 characters   | 1/4.3B      | ~4,294,967,296    | ~26.5 hours            | ~7.2 hours              |

**Note:** These are *expected* values. Actual time may vary significantly due to randomness.

### Combined Prefix and Postfix

When using both `--prefix` and `--postfix`, the probabilities multiply:

- `--prefix ab --postfix cd` (2+2 chars) = 1/(256 × 256) = 16^4 = ~65,536 attempts
- `--prefix cafe --postfix babe` (4+4 chars) = 16^8 = ~4.3 billion attempts

## Performance Optimization Tips

### 1. Worker Count

By default, the tool uses `GOMAXPROCS`, which normally reflects the process CPU
allowance. You can adjust this between 1 and 256:

```bash
# Use half the cores (may reduce heat/power consumption)
./lxmf-vanity --prefix abc --workers 4

# Use more workers than cores (usually not beneficial)
./lxmf-vanity --prefix abc --workers 16
```

**Recommendation:** Start with the default, then try a few worker counts and use the best measured `avg` rate for your machine. On heterogeneous CPUs, such as Apple Silicon performance/efficiency core systems, the default is not always optimal.

### 2. Pattern Selection

Choose patterns wisely:

- **Easy:** Short prefixes (3-5 chars) or short postfixes
- **Acceptable:** 6-character prefix or postfix
- **Challenging:** 7-character patterns (minutes to hours)
- **Very Hard:** 8+ character patterns (hours to days)

### 3. System Resources

The program is CPU-bound and uses:
- **CPU:** Near 100% on all workers
- **Memory:** ~10-20 MB (lightweight)
- **Disk:** Only writes when a match is found

### 4. Optimized Builds

`make build` produces a stripped, path-trimmed, cgo-free release binary:

```bash
make build
```

The release flags are:

- `CGO_ENABLED=0` - avoids accidental cgo linkage
- `-buildmode=pie` - emits position-independent executables for platform ASLR
- `-trimpath -buildvcs=false` - removes local path and VCS metadata from the binary
- `-ldflags "-s -w -buildid="` - strips symbols/debug data and removes the build ID

Use `make build-debug` when you need symbols for profiling or debugger work. On private x86_64 builds where you control the target CPU, you can also test a newer microarchitecture level, for example `GOAMD64=v3 make build`; do not use that for broad distribution unless you are comfortable dropping older CPU support.

### 5. Benchmarking

To measure your system's performance:

```bash
# Stable benchmark using the complete secure generation path.
./lxmf-vanity --benchmark 30s

# Compare worker counts on your machine.
./lxmf-vanity --benchmark 30s --workers 4
./lxmf-vanity --benchmark 30s --workers 8
```

Use the final average rate. Benchmark mode runs entropy acquisition, both curve
operations and LXMF hashing, but intentionally never selects an identity as a
winner.

`--dry-run` remains available for testing match behavior, but it stops at a
match and irreversibly discards that private identity. It should not be used for
performance measurement.

## Measured Performance Examples

The numbers below are observed total attempts per second for the current full-identity generator. They are examples, not guaranteed targets.

| System | Workers | Build | Observed avg speed |
|--------|---------|-------|--------------------|
| Apple M1 on macOS | 8 | Go 1.26.3 | ~40K-45K/s |
| Apple M4 on macOS | 10 | Go 1.26.3 | ~165K-167K/s |
| Intel i7 10th gen on Windows | 12 | prebuilt windows/amd64 binary | ~44K/s |
| Raspberry Pi 4 B | 4 | prebuilt linux/arm64 binary | ~11K/s |

## Theoretical Limits

The current implementation keeps the matching path cheap:
- No hex string conversion in the hot path
- Predecoded byte/nibble comparisons for prefix and suffix matching
- No per-attempt heap escape for the candidate identity
- Batched per-worker attempt counters to reduce atomic contention
- Low allocation count concentrated in the standard Ed25519 derivation path

Most time is spent deriving X25519 and Ed25519 public keys. Potential changes
must be benchmarked and checked against the pinned Reticulum vector. Safe areas
to investigate include larger worker-local reads from `crypto/rand` and reducing
temporary allocations while retaining standard, reviewed cryptographic APIs.

Platform-specific or GPU curve implementations are not drop-in optimizations:
they require independent security review and exhaustive byte-for-byte vectors.
The candidate generator must never be replaced with a non-cryptographic PRNG.

## Real-World Examples

### Example 1: Simple Prefix
```
$ ./lxmf-vanity --prefix cafe
Searching for LXMF vanity address...
  Prefix:  cafe
  Workers: 8

  Speed: 43.50K/s (avg: 43.20K/s) | Total: 86.80K
✓ Found matching address: cafe46ea7bac86f0ca4ac7e5c8515b91
  Total attempts: 90012
```

**Analysis:** A 4-character prefix is usually found within a few seconds on a machine around 45K/s.

### Example 2: Benchmark Run
```
$ ./lxmf-vanity --benchmark 30s --workers 8
Benchmarking full LXMF identity generation...
  Duration: 30s
  Workers: 8

  Speed: 43.34K/s (avg: 42.93K/s) | Total: 43.34K
  Speed: 42.43K/s (avg: 42.55K/s) | Total: 85.77K
  Speed: 43.53K/s (avg: 42.98K/s) | Total: 129.30K

Benchmark complete: 1.29M attempts (43.00K/s average)
```

**Analysis:** Use the average speed from a run like this for estimates. At ~43K/s, an 8-character prefix has an expected time of roughly 28 hours.

## Luck Factor

Due to randomness, you might find a pattern much faster or slower than expected:
- **Lucky:** Finding an 8-char pattern in 1 million attempts (0.02% of expected)
- **Unlucky:** Taking 100 million attempts for a 6-char pattern (6× expected)

This is normal! The expected values are averages.

## Monitoring Progress

The tool shows real-time statistics:
- **Speed:** Current attempts per second (1-second window)
- **Avg:** Average attempts per second since start
- **Total:** Total attempts made so far

The search is geometrically distributed. Before a search, the expected number
of attempts is `16^pattern_length`. After any number of failed attempts, the
conditional expected number of *additional* attempts is still
`16^pattern_length`; success does not become due. A useful progress measure is
the cumulative probability that a match would have occurred by attempt `n`:

```
P(found by n) = 1 - (1 - 16^-pattern_length)^n
```
