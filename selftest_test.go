package main

import (
	"strings"
	"testing"
)

func TestKnownAnswerSelfTest(t *testing.T) {
	expected := knownAnswerIdentity()
	if err := selfTest(expected); err != nil {
		t.Fatal(err)
	}
	expected.Address[0] ^= 1
	if err := selfTest(expected); err == nil || !strings.Contains(err.Error(), "self-test failed") {
		t.Fatal("corrupt expectation accepted")
	}
}
func BenchmarkStartupSelfTest(b *testing.B) {
	expected := knownAnswerIdentity()
	for b.Loop() {
		if err := selfTest(expected); err != nil {
			b.Fatal(err)
		}
	}
}
