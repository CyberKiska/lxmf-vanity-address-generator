package main

import (
	"math"
	"testing"
)

func TestProbabilityAndMemorylessRemainingEstimates(t *testing.T) {
	for _, k := range []int{1, 4, 8, 32} {
		if successProbability(k, 0) != 0 {
			t.Fatal("zero attempt probability")
		}
		p := math.Exp2(float64(-4 * k))
		if math.Abs(successProbability(k, 1)-p) > p*1e-12 {
			t.Fatal("unstable one-attempt probability")
		}
		before := remainingSeconds(k, 1000, .5)
		_ = successProbability(k, 1000000)
		if before != remainingSeconds(k, 1000, .5) {
			t.Fatal("failed attempts changed remaining distribution")
		}
		if !math.IsInf(remainingSeconds(k, 0, .5), 1) {
			t.Fatal("zero rate estimate")
		}
		line := progressLine(^uint64(0), 1, 1, k)
		if len(line) > 99 {
			t.Fatalf("long progress line: %d: %s", len(line), line)
		}
		if estimateTime(remainingSeconds(k, 1, .95)) == "unknown" {
			t.Fatal("large-time overflow")
		}
	}
	if got := successProbability(1, 16); math.Abs(got-(1-math.Pow(15.0/16, 16))) > 1e-12 {
		t.Fatal("geometric probability mismatch")
	}
	if got := remainingSeconds(1, 1, .5); got != 11 {
		t.Fatalf("median attempts %g", got)
	}
	if !math.IsNaN(successProbability(33, 1)) {
		t.Fatal("invalid pattern estimate")
	}
}
