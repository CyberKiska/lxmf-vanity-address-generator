package main

import (
	"context"
	"errors"
	"testing"
)

func TestAttemptLimitIsExactAndKeepsWinner(t *testing.T) {
	for _, workers := range []int{1, 8} {
		matcher, _ := newAddressMatcher("0", "")
		search := newSearcher(matcher, &repeatingReader{pattern: goldenRandomInput(t)})
		search.maxAttempts = 7
		var winner Identity
		err := search.run(context.Background(), workers, &winner)
		if !errors.Is(err, errAttemptLimit) || search.attempts.Load() != 7 {
			t.Fatalf("attempt limit: %v / %d", err, search.attempts.Load())
		}
	}
	search := newSearcher(addressMatcher{}, &repeatingReader{pattern: goldenRandomInput(t)})
	search.maxAttempts = 1
	var winner Identity
	if err := search.run(context.Background(), 8, &winner); err != nil {
		t.Fatal("in-flight winner lost at limit")
	}
	if search.attempts.Load() != 1 || search.workerWarning != nil {
		t.Fatal("limit generated extra attempt/warning")
	}
}
