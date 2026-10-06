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

func TestSegmentedSelfTestDetectsBrokenTransform(t *testing.T) {
	if err := selfTestSegmented(func(identity *Identity, public *[64]byte, material *[26]byte) {
		rederiveSigningHalf(identity, public, material)
		identity.Hash[0] ^= 1
	}); err == nil {
		t.Fatal("broken signing-half transform accepted")
	}
}
