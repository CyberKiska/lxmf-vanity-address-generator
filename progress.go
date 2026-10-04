package main

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"sync/atomic"
	"time"
)

func monitorProgress(ctx context.Context, attempts *atomic.Uint64, writer io.Writer) {
	ticker := time.NewTicker(time.Second)
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
			fmt.Fprintf(writer, "\r  Speed: %s/s (avg: %s/s) | Total: %s        ",
				formatNumber(rate),
				formatNumber(avgRate),
				formatNumber(current))
		}
	}
}

func attemptsPerSecond(attempts uint64, elapsed time.Duration) uint64 {
	if elapsed <= 0 {
		return 0
	}
	return uint64(float64(attempts) / elapsed.Seconds())
}

func formatNumber(n uint64) string {
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
