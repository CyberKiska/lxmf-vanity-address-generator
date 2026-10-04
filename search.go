package main

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

type searcher struct {
	matcher     addressMatcher
	rng         io.Reader
	stopOnMatch bool
	attempts    atomic.Uint64
}

type searchOutcome struct {
	identity Identity
	err      error
}

func newSearcher(matcher addressMatcher, rng io.Reader) *searcher {
	return &searcher{matcher: matcher, rng: rng, stopOnMatch: true}
}

func (s *searcher) run(parent context.Context, workerCount int) (Identity, error) {
	if workerCount < 1 || workerCount > maxWorkerCount {
		return Identity{}, fmt.Errorf("invalid worker count %d", workerCount)
	}
	if s.rng == nil {
		return Identity{}, fmt.Errorf("secure random source is nil")
	}
	s.attempts.Store(0)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	outcomes := make(chan searchOutcome, 1)
	var publishOnce sync.Once
	publish := func(outcome searchOutcome) {
		defer wipeIdentitySecrets(&outcome.identity)
		publishOnce.Do(func() {
			outcomes <- outcome
			cancel()
		})
	}

	var workersDone sync.WaitGroup
	workersDone.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go s.worker(ctx, &workersDone, publish)
	}

	var outcome searchOutcome
	defer wipeIdentitySecrets(&outcome.identity)
	select {
	case outcome = <-outcomes:
	case <-parent.Done():
		cancel()
		workersDone.Wait()
		// An in-flight candidate can finish during cancellation. Preserve its
		// published result instead of discarding a completed private identity.
		select {
		case outcome = <-outcomes:
		default:
			return Identity{}, parent.Err()
		}
	}

	cancel()
	workersDone.Wait()
	if outcome.err != nil {
		return Identity{}, outcome.err
	}
	return outcome.identity, nil
}

func (s *searcher) worker(ctx context.Context, workersDone *sync.WaitGroup, publish func(searchOutcome)) {
	defer workersDone.Done()

	var localAttempts uint64
	defer flushAttempts(&localAttempts, &s.attempts)

	var randBuf [identityPrivateKeySize]byte
	var identity Identity
	var publicKey [64]byte
	addrHashMaterial := newAddressHashMaterial()
	defer wipeBytes(randBuf[:])
	defer wipeIdentitySecrets(&identity)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if _, err := io.ReadFull(s.rng, randBuf[:]); err != nil {
			publish(searchOutcome{err: fmt.Errorf("secure random source failed: %w", err)})
			return
		}

		if err := deriveCandidate(&identity, &randBuf, &publicKey, &addrHashMaterial); err != nil {
			publish(searchOutcome{err: err})
			return
		}

		localAttempts++
		if localAttempts >= attemptFlushInterval {
			flushAttempts(&localAttempts, &s.attempts)
		}

		if s.stopOnMatch && s.matcher.matches(identity.Address[:]) {
			publish(searchOutcome{identity: identity})
			return
		}
	}
}

func flushAttempts(localAttempts *uint64, totalAttempts *atomic.Uint64) {
	if *localAttempts == 0 {
		return
	}
	totalAttempts.Add(*localAttempts)
	*localAttempts = 0
}
