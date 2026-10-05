package main

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

func TestSearcherErrorCannotSuppressInFlightWinner(t *testing.T) {
	raw := goldenRandomInput(t)
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		search := newSearcher(addressMatcher{}, readerFunc(func(p []byte) (int, error) {
			if calls.Add(1) == 1 {
				<-release
				return copy(p, raw), nil
			}
			return 0, io.ErrUnexpectedEOF
		}))
		var identity Identity
		var err error
		done := make(chan struct{})
		go func() { err = search.run(context.Background(), 2, &identity); close(done) }()
		synctest.Wait()
		close(release)
		<-done
		if err != nil {
			t.Fatalf("completed winner suppressed: %v", err)
		}
		if search.workerWarning == nil || !errors.Is(search.workerWarning, io.ErrUnexpectedEOF) {
			t.Fatal("worker warning lost")
		}
		if identity.Address != goldenIdentity(t).Address {
			t.Fatal("wrong winner")
		}

	})
}
