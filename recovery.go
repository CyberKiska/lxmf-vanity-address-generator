package main

import (
	"fmt"
	"os"
	"time"
)

// The timer bounds retries between operations; it cannot interrupt kernel I/O.
// Search cancellation never implicitly discards a validated winner.
func recoverWinner(attempt func() saveResult, interrupts <-chan os.Signal, timeout time.Duration, c *console, enter func()) (saveResult, bool) {
	delay := time.Second
	var deadline, armed time.Time
	started := false
	var previous saveResult
	for {
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			previous.cause = fmt.Errorf("save recovery deadline reached; retained files are not claimed erased")
			return previous, false
		}
		result := attempt()
		for _, warning := range previous.Deviations {
			result.Deviations = appendUnique(result.Deviations, warning)
		}
		// A verified path must not also be labelled unverified after a retry.
		var unverified []string
		for _, path := range result.Unverified {
			found := false
			for _, verified := range result.Verified {
				if path == verified {
					found = true
				}
			}
			if !found {
				unverified = append(unverified, path)
			}
		}
		result.Unverified = unverified
		if result.saved() || result.internal {
			return result, false
		}
		previous = result
		if !started {
			started = true
			if timeout > 0 {
				deadline = time.Now().Add(timeout)
			}
			enter()
		}
		c.status("Save recovery: %v; retry in %s. Two fresh Ctrl-C presses within 10s discard memory; retained files remain.\n", result.cause, delay)
		wait := delay
		if !deadline.IsZero() {
			wait = min(wait, time.Until(deadline))
			if wait <= 0 {
				continue
			}
		}
		timer := time.NewTimer(wait)
	waiting:
		for {
			select {
			case <-timer.C:
				break waiting
			case sig, ok := <-interrupts:
				if !ok {
					interrupts = nil
					continue
				}
				if sig != os.Interrupt {
					continue
				}
				now := time.Now()
				if !armed.IsZero() && now.Sub(armed) <= 10*time.Second {
					timer.Stop()
					previous.cause = fmt.Errorf("in-memory winner explicitly abandoned; retained files are not claimed erased")
					return previous, true
				}
				armed = now
				c.status("Discard armed for 10s: press Ctrl-C again to abandon the in-memory winner.\n")
			}
		}
		delay = min(delay*2, 30*time.Second)
	}
}
