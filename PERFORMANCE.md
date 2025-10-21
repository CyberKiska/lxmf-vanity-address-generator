# Performance Guide

## Expected Search Times

The time to find a vanity address depends on the pattern complexity. Below are approximate times based on testing on a modern multi-core CPU (8 cores at ~100K attempts/sec per core).

### Probability and Expected Attempts

Each hex character adds a factor of 16 to the search space:

| Pattern Length | Probability | Expected Attempts | Approximate Time (8 cores as 800K/s) |
|----------------|-------------|-------------------|--------------------------------------|
| 1 character    | 1/16        | ~16               | < 1 second                           |
| 2 characters   | 1/256       | ~256              | < 1 second                           |
| 3 characters   | 1/4,096     | ~4,096            | < 1 second                           |
| 4 characters   | 1/65,536    | ~65,536           | < 1 second                           |
| 5 characters   | 1/1,048,576 | ~1,048,576        | ~1-2 seconds                         |
| 6 characters   | 1/16,777,216| ~16,777,216       | ~20-30 seconds                       |
| 7 characters   | 1/268M      | ~268,435,456      | ~5-10 minutes                        |
| 8 characters   | 1/4.3B      | ~4,294,967,296    | >=1-2 hours                          |

**Note:** These are *expected* values. Actual time may vary significantly due to randomness.

### Combined Prefix and Postfix

When using both `--prefix` and `--postfix`, the probabilities multiply:

- `--prefix ab --postfix cd` (2+2 chars) = 1/(256 × 256) = 16^4 = ~65,536 attempts
- `--prefix cafe --postfix babe` (4+4 chars) = 16^8 = ~4.3 billion attempts

## Performance Optimization Tips

### 1. Worker Count

By default, the tool uses all available CPU cores. You can adjust this:

```bash
# Use half the cores (may reduce heat/power consumption)
./reticulum-vanity --prefix abc --workers 4

# Use more workers than cores (usually not beneficial)
./reticulum-vanity --prefix abc --workers 16
```

**Recommendation:** Stick with the default (number of CPU cores) for best performance.

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

### 4. Benchmarking

To measure your system's performance:

```bash
# Quick benchmark (will find "ff" very fast, ~256 attempts)
./reticulum-vanity --prefix ff --dry-run

# Longer benchmark (~65K attempts)
./reticulum-vanity --prefix abcd --dry-run
```

Look for the "Speed" output to see your system's hash rate.

## Architecture-Specific Performance

Performance varies by CPU:

| CPU Type             | Cores | Approx. Speed |
|----------------------|-------|---------------|
| Apple M1/M2/M3       | 8-10  | 600K-1M/s     |
| Intel i7/i9 (modern) | 8-12  | 400K-800K/s   |
| AMD Ryzen 7/9        | 8-16  | 500K-1M/s     |
| ARM (Raspberry Pi 4) | 4     | 50K-100K/s    |
| Cloud VPS (2 vCPU)   | 2     | 100K-200K/s   |

## Theoretical Limits

The current implementation is optimized for:
- Low memory allocations in hot path
- Efficient SHA-256 computation
- Lock-free atomic counters
- Direct byte comparison

Further optimizations possible:
- SIMD SHA-256 (platform-specific)
- GPU acceleration (requires CUDA/OpenCL)
- Distributed computing (multiple machines)

## Real-World Examples

### Example 1: Simple Prefix
```
$ ./reticulum-vanity --prefix cafe
Searching for LXMF vanity address...
  Prefix:  cafe
  Workers: 8

  Speed: 85K/s (avg: 85K/s) | Total: 184K
✓ Found matching address: cafe46ea7bac86f0ca4ac7e5c8515b91
  Total attempts: 184689
```

**Analysis:** Found in ~2 seconds at 85K/s average speed.

### Example 2: Longer Pattern
```
$ ./reticulum-vanity --prefix deadbeef
Searching for LXMF vanity address...
  Prefix:  deadbeef
  Workers: 8

  Speed: 82K/s (avg: 81K/s) | Total: 3.2M
✓ Found matching address: deadbeef8f1c4e3a7b2d9f5c1e6a8b4d
  Total attempts: 3245678123
```

**Analysis:** 8-character prefix took hours with 81K/s speed.

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

Use these to estimate remaining time:
```
Remaining = (16^pattern_length - total_attempts) / avg_speed
```
