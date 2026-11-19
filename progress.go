package main

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"sync/atomic"
	"time"
)

func monitorProgress(ctx context.Context, attempts *atomic.Uint64, c *console, terminal bool, patternLength int) {
	interval := time.Minute
	if terminal {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	lastAttempts := uint64(0)
	startTime := time.Now()
	lastTime := startTime
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			current := attempts.Load()
			rate := attemptsPerSecond(current-lastAttempts, now.Sub(lastTime))
			lastAttempts = current
			lastTime = now
			avgRate := attemptsPerSecond(current, now.Sub(startTime))
			line := progressLine(current, rate, avgRate, patternLength)
			if terminal {
				c.status("\r%-99s", line)
			} else {
				c.status("%s\n", line)
			}
		}
	}
}

func attemptsPerSecond(attempts uint64, elapsed time.Duration) uint64 {
	if elapsed <= 0 {
		return 0
	}
	rate := float64(attempts) / elapsed.Seconds()
	if rate >= float64(^uint64(0)) {
		return ^uint64(0)
	}
	return uint64(rate)
}

func formatNumber(n uint64) string {
	if n >= 1_000_000_000_000 {
		return fmt.Sprintf("%.2e", float64(n))
	}
	if n >= 1_000_000_000 {
		return fmt.Sprintf("%.2fG", float64(n)/1_000_000_000)
	}
	if n >= 1_000_000 {
		return fmt.Sprintf("%.2fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.2fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

func expectedAttempts(patternHexCharacters int) string {
	if patternHexCharacters < 0 || patternHexCharacters > addressHexLength {
		return "invalid"
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(4*patternHexCharacters)).String()
}

// These estimates assume pseudorandom hashes. Failed attempts do not make the
// remaining geometric waiting time shorter (the distribution is memoryless).
func successProbability(k int, n uint64) float64 {
	if n == 0 {
		return 0
	}
	if k < 1 || k > addressHexLength {
		return math.NaN()
	}
	p := math.Exp2(float64(-4 * k))
	return -math.Expm1(float64(n) * math.Log1p(-p))
}
func remainingSeconds(k int, rate uint64, q float64) float64 {
	if rate == 0 {
		return math.Inf(1)
	}
	if k < 1 || k > addressHexLength || q <= 0 || q >= 1 {
		return math.NaN()
	}
	p := math.Exp2(float64(-4 * k))
	return math.Ceil(math.Log1p(-q)/math.Log1p(-p)) / float64(rate)
}
func estimateTime(seconds float64) string {
	if math.IsInf(seconds, 1) || math.IsNaN(seconds) {
		return "unknown"
	}
	if seconds < 60 {
		return fmt.Sprintf("%.1fs", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%.1fm", seconds/60)
	}
	if seconds < 86400 {
		return fmt.Sprintf("%.1fh", seconds/3600)
	}
	if seconds < 31557600 {
		return fmt.Sprintf("%.1fd", seconds/86400)
	}
	years := seconds / 31557600
	if years >= 1e6 {
		return fmt.Sprintf("%.1ey", years)
	}
	return fmt.Sprintf("%.1fy", years)
}
func progressLine(attempts, rate, average uint64, k int) string {
	if k == 0 {
		return fmt.Sprintf("%s/s avg %s/s | attempts %s", formatNumber(rate), formatNumber(average), formatNumber(attempts))
	}
	return fmt.Sprintf("%s/s | n %s | estimated succeeded %.1f%% | next 50%% %s, 95%% %s",
		formatNumber(rate), formatNumber(attempts), 100*successProbability(k, attempts), estimateTime(remainingSeconds(k, average, .5)), estimateTime(remainingSeconds(k, average, .95)))
}
