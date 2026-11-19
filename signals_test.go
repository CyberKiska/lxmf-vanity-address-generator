package main

import (
	"context"
	"io"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

func TestSaveSignalsCannotArmRecoveryDiscard(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		input := make(chan os.Signal, 16)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		owner := newSignalOwner(input, cancel)
		defer owner.close()
		owner.phase("save")
		input <- os.Interrupt
		input <- os.Interrupt
		synctest.Wait()
		if ctx.Err() != nil {
			t.Fatal("save signal cancelled winner context")
		}
		owner.phase("recovery")
		select {
		case <-owner.recovery:
			t.Fatal("save signal leaked into discard confirmation")
		default:
		}
		c := newConsole(io.Discard)
		defer c.close(time.Second)
		done := make(chan struct{})
		discard := false
		go func() {
			_, discard = recoverWinner(func() saveResult { return saveResult{cause: io.ErrClosedPipe} }, owner.recovery, 0, c, func() {})
			close(done)
		}()
		synctest.Wait()
		input <- os.Interrupt
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("one fresh interrupt discarded winner")
		default:
		}
		input <- os.Interrupt
		<-done
		if !discard {
			t.Fatal("fresh recovery confirmation ignored")
		}
	})
}
