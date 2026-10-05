package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

const defaultSegmentLength = 1 << 16

var errAttemptLimit = errors.New("search attempt limit reached")

type searcher struct {
	maxAttempts   uint64
	segmentLength int
	reserved      atomic.Uint64
	limited       atomic.Bool
	matcher       addressMatcher
	rng           io.Reader
	stopOnMatch   bool
	attempts      atomic.Uint64
	workerWarning error
}

func newSearcher(matcher addressMatcher, rng io.Reader) *searcher {
	return &searcher{matcher: matcher, rng: rng, stopOnMatch: true, segmentLength: defaultSegmentLength}
}

func (s *searcher) run(parent context.Context, workerCount int, result *Identity) error {
	if result == nil {
		return fmt.Errorf("nil winner buffer")
	}
	if workerCount < 1 || workerCount > maxWorkerCount {
		return fmt.Errorf("invalid worker count %d", workerCount)
	}
	if s.segmentLength < 1 {
		return fmt.Errorf("segment length must be positive")
	}
	if s.rng == nil {
		return fmt.Errorf("secure random source is nil")
	}
	s.attempts.Store(0)
	s.reserved.Store(0)
	s.limited.Store(false)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// A worker error and a completed winner have separate slots. Joining all
	// workers permits an in-flight match to win even after another worker fails.
	var winnerOnce, errorOnce sync.Once
	var found bool
	var firstError error
	publish := func(identity *Identity, err error) {
		if errors.Is(err, errAttemptLimit) {
			s.limited.Store(true)
			cancel()
			return
		}
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
	if s.limited.Load() {
		return errAttemptLimit
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

	left := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !s.reserveAttempt() {
			publish(nil, errAttemptLimit)
			return
		}
		if left == 0 {
			if _, err := io.ReadFull(s.rng, randBuf[:]); err != nil {
				wipeBytes(randBuf[:])
				publish(nil, fmt.Errorf("secure random source failed: %w", err))
				return
			}
			err := deriveCandidate(&identity, &randBuf, &publicKey, &addrHashMaterial)
			wipeBytes(randBuf[:])
			if err != nil {
				publish(nil, err)
				return
			}
			left = s.segmentLength - 1
		} else {
			if _, err := io.ReadFull(s.rng, identity.Ed25519Seed[:]); err != nil {
				publish(nil, fmt.Errorf("secure random source failed: %w", err))
				return
			}
			rederiveSigningHalf(&identity, &publicKey, &addrHashMaterial)
			left--
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

func (s *searcher) reserveAttempt() bool {
	if s.maxAttempts == 0 {
		return true
	}
	for {
		n := s.reserved.Load()
		if n >= s.maxAttempts {
			return false
		}
		if s.reserved.CompareAndSwap(n, n+1) {
			return true
		}
	}
}
