package main

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

type searcher struct {
	matcher       addressMatcher
	rng           io.Reader
	stopOnMatch   bool
	attempts      atomic.Uint64
	workerWarning error
}

func newSearcher(matcher addressMatcher, rng io.Reader) *searcher {
	return &searcher{matcher: matcher, rng: rng, stopOnMatch: true}
}

func (s *searcher) run(parent context.Context, workerCount int, result *Identity) error {
	if result == nil {
		return fmt.Errorf("nil winner buffer")
	}
	if workerCount < 1 || workerCount > maxWorkerCount {
		return fmt.Errorf("invalid worker count %d", workerCount)
	}
	if s.rng == nil {
		return fmt.Errorf("secure random source is nil")
	}
	s.attempts.Store(0)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// A worker error and a completed winner have separate slots. Joining all
	// workers permits an in-flight match to win even after another worker fails.
	var winnerOnce, errorOnce sync.Once
	var found bool
	var firstError error
	publish := func(identity *Identity, err error) {
		if err != nil {
			errorOnce.Do(func() { firstError = err })
			cancel()
			return
		}
		winnerOnce.Do(func() { *result = *identity; found = true })
		cancel()
	}
	var workersDone sync.WaitGroup
	workersDone.Add(workerCount)
	for range workerCount {
		go s.worker(ctx, &workersDone, publish)
	}
	workersDone.Wait()
	s.workerWarning = firstError
	if found {
		return nil
	}
	if firstError != nil {
		return firstError
	}
	return parent.Err()
}

func (s *searcher) worker(ctx context.Context, workersDone *sync.WaitGroup, publish func(*Identity, error)) {
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
			publish(nil, fmt.Errorf("secure random source failed: %w", err))
			return
		}

		if err := deriveCandidate(&identity, &randBuf, &publicKey, &addrHashMaterial); err != nil {
			publish(nil, err)
			return
		}

		localAttempts++
		if localAttempts >= attemptFlushInterval {
			flushAttempts(&localAttempts, &s.attempts)
		}

		if s.stopOnMatch && s.matcher.matches(identity.Address[:]) {
			publish(&identity, nil)
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
