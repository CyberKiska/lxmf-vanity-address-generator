package main

import (
	"errors"
	"io"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

func TestRecoveryBackoffAndDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newConsole(io.Discard)
		defer c.close(time.Second)
		start := time.Now()
		calls := 0
		result, discard := recoverWinner(func() saveResult {
			calls++
			if calls == 4 {
				return saveResult{Verified: []string{"verified"}}
			}
			return saveResult{cause: errors.New("disk unavailable")}
		}, make(chan os.Signal), 0, c, func() {})
		if discard || !result.saved() || time.Since(start) != 7*time.Second {
			t.Fatalf("backoff: calls %d elapsed %s", calls, time.Since(start))
		}
		start = time.Now()
		result, discard = recoverWinner(func() saveResult { return saveResult{cause: errors.New("disk unavailable")} }, make(chan os.Signal), 2500*time.Millisecond, c, func() {})
		if discard || result.saved() || time.Since(start) != 2500*time.Millisecond {
			t.Fatal("deadline not applied")
		}
	})
}
func TestRecoveryRequiresTwoFreshInterrupts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newConsole(io.Discard)
		defer c.close(time.Second)
		input := make(chan os.Signal)
		done := make(chan struct{})
		discard := false
		go func() {
			_, discard = recoverWinner(func() saveResult { return saveResult{cause: errors.New("disk unavailable")} }, input, 0, c, func() {})
			close(done)
		}()
		synctest.Wait()
		input <- os.Interrupt
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("one interrupt discarded winner")
		default:
		}
		input <- os.Interrupt
		<-done
		if !discard {
			t.Fatal("fresh confirmation ignored")
		}
	})
}
