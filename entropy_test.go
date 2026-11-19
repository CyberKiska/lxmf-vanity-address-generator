package main

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestIndependentEntropyAccountingAndPartialFailures(t *testing.T) {
	for _, partial := range []int{0, 1, 31, 63} {
		search := newSearcher(addressMatcher{}, readerFunc(func(p []byte) (int, error) { return partial, io.ErrUnexpectedEOF }))
		var winner Identity
		if err := search.run(context.Background(), 1, &winner); !errors.Is(err, io.ErrUnexpectedEOF) || search.attempts.Load() != 0 {
			t.Fatal("partial entropy counted as candidate")
		}
	}
	rng := &countingReader{reader: &repeatingReader{pattern: goldenRandomInput(t)}}
	search := newSearcher(addressMatcher{}, rng)
	search.segmentLength = 1
	search.stopOnMatch = false
	search.maxAttempts = 9
	var winner Identity
	if err := search.run(context.Background(), 1, &winner); !errors.Is(err, errAttemptLimit) {
		t.Fatal(err)
	}
	if rng.BytesRead() != 64*search.attempts.Load() {
		t.Fatal("independent entropy consumption changed")
	}
}
