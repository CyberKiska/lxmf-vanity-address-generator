package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
)

// PUBLIC TEST DATA: one continuous byte stream, independent of read boundaries.
type streamReader struct {
	mu     sync.Mutex
	stream []byte
	offset int
}

func (r *streamReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.offset+len(p) > len(r.stream) {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, r.stream[r.offset:])
	r.offset += n
	return n, nil
}
func TestSegmentedDifferentialCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/rns-identity-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Vectors []struct{ Raw string } }
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, vector := range corpus.Vectors {
		var input [64]byte
		copy(input[:], mustDecodeHex(t, vector.Raw))
		var actual, expected Identity
		var public [64]byte
		material := newAddressHashMaterial()
		if err := deriveCandidate(&actual, &input, &public, &material); err != nil {
			t.Fatal(err)
		}
		for i := 32; i < 64; i++ {
			input[i] ^= 0xa5
		}
		copy(actual.Ed25519Seed[:], input[32:])
		rederiveSigningHalf(&actual, &public, &material)
		if err := deriveCandidate(&expected, &input, &public, &material); err != nil {
			t.Fatal(err)
		}
		if actual != expected {
			t.Fatal("segmented corpus differential mismatch")
		}
		if err := validateIdentityConsistency(&actual); err != nil {
			t.Fatal(err)
		}
	}
	for range 16 {
		var input [64]byte
		rand.Read(input[:])
		var actual, expected Identity
		var public [64]byte
		material := newAddressHashMaterial()
		if err := deriveCandidate(&actual, &input, &public, &material); err != nil {
			t.Fatal(err)
		}
		rand.Read(input[32:])
		copy(actual.Ed25519Seed[:], input[32:])
		rederiveSigningHalf(&actual, &public, &material)
		if err := deriveCandidate(&expected, &input, &public, &material); err != nil {
			t.Fatal(err)
		}
		if actual != expected {
			t.Fatal("random differential mismatch")
		}
	}
}
func segmentStream(t *testing.T, segment, n int) ([]byte, *Identity) {
	var stream []byte
	var input [64]byte
	var expected Identity
	for i := range n {
		if i%segment == 0 {
			for j := range input {
				input[j] = byte(i*17 + j)
			}
			stream = append(stream, input[:]...)
		} else {
			for j := 32; j < 64; j++ {
				input[j] = byte(i*19 + j)
			}
			stream = append(stream, input[32:]...)
		}
		var public [64]byte
		material := newAddressHashMaterial()
		if err := deriveCandidate(&expected, &input, &public, &material); err != nil {
			t.Fatal(err)
		}
	}
	return stream, &expected
}
func TestSegmentedLaterWinnerAndBoundary(t *testing.T) {
	for _, segment := range []int{1, 3, 1000} {
		for _, n := range []int{1, 2, 3, 4, 7} {
			stream, expected := segmentStream(t, segment, n)
			matcher, _ := newAddressMatcher(hex.EncodeToString(expected.Address[:]), "")
			reader := &streamReader{stream: stream}
			search := newSearcher(matcher, reader)
			search.segmentLength = segment
			var winner Identity
			if err := search.run(context.Background(), 1, &winner); err != nil {
				t.Fatal(err)
			}
			if winner != *expected || search.attempts.Load() != uint64(n) || reader.offset != 32*n+32*((n+segment-1)/segment) {
				t.Fatal("winner/boundary/entropy mismatch")
			}
		}
	}
}
func TestSegmentedEntropyAccounting(t *testing.T) {
	for _, segment := range []int{1, 4, 1000} {
		const n = 17
		stream, _ := segmentStream(t, segment, n)
		reader := &streamReader{stream: stream}
		search := newSearcher(addressMatcher{}, reader)
		search.segmentLength = segment
		search.stopOnMatch = false
		search.maxAttempts = n
		var winner Identity
		if err := search.run(context.Background(), 1, &winner); !errors.Is(err, errAttemptLimit) {
			t.Fatal(err)
		}
		if reader.offset != 32*n+32*((n+segment-1)/segment) || search.attempts.Load() != n {
			t.Fatal("segmented accounting mismatch")
		}
	}
}
func TestSegmentedSteadyStateAllocatesNothing(t *testing.T) {
	identity := goldenIdentity(t)
	var public [64]byte
	copy(public[:32], identity.X25519Public[:])
	material := newAddressHashMaterial()
	if n := testing.AllocsPerRun(100, func() { rederiveSigningHalf(&identity, &public, &material) }); n != 0 {
		t.Fatalf("steady state allocates: %g", n)
	}
}
