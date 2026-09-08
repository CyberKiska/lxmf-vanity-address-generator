package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	goldenX25519Private = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e5f"
	goldenX25519Public  = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
	goldenEd25519Seed   = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	goldenEd25519Public = "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"
	goldenIdentityHash  = "aca31af0441d81dbec71e82da0b4b5f5"
	goldenLXMFAddress   = "fae321c442e3c9bdcd7a3e79d850e03c"
)

// Preserve the original RNS 1.4.2 regression vector alongside the larger corpus
// checked against every reference version and provider in CI.
func TestDeriveCandidateMatchesReticulum142GoldenVector(t *testing.T) {
	identity := goldenIdentity(t)

	assertHexEqual(t, "X25519 private", identity.X25519Private[:], goldenX25519Private)
	assertHexEqual(t, "X25519 public", identity.X25519Public[:], goldenX25519Public)
	assertHexEqual(t, "Ed25519 seed", identity.Ed25519Seed[:], goldenEd25519Seed)
	assertHexEqual(t, "Ed25519 public", identity.Ed25519Public[:], goldenEd25519Public)
	assertHexEqual(t, "identity hash", identity.Hash[:], goldenIdentityHash)
	assertHexEqual(t, "LXMF address", identity.Address[:], goldenLXMFAddress)
}

func TestGoldenConstantsMatchPinnedFixture(t *testing.T) {
	fixtureData, err := os.ReadFile(filepath.Join("testdata", "rns-1.4.2-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		RNSVersion                         string `json:"rns_version"`
		RNSReferenceCommit                 string `json:"rns_reference_commit"`
		RawCandidateInput                  string `json:"raw_candidate_input"`
		X25519Private                      string `json:"x25519_private"`
		X25519Public                       string `json:"x25519_public"`
		Ed25519Seed                        string `json:"ed25519_seed"`
		Ed25519Public                      string `json:"ed25519_public"`
		IdentityHash                       string `json:"identity_hash"`
		LXMFNameHash                       string `json:"lxmf_name_hash"`
		LXMFAddress                        string `json:"lxmf_address"`
		CanonicalPrivateRoundtrip          bool   `json:"canonical_private_roundtrip"`
		UnmaskedPrivateRoundtripPreserved  bool   `json:"unmasked_private_roundtrip_preserved"`
		UnmaskedAndCanonicalAddressesEqual bool   `json:"unmasked_and_canonical_addresses_equal"`
	}
	if err := json.Unmarshal(fixtureData, &fixture); err != nil {
		t.Fatal(err)
	}

	if fixture.RNSVersion != "1.4.2" {
		t.Fatalf("fixture RNS version = %q", fixture.RNSVersion)
	}
	if fixture.RNSReferenceCommit != "b48b96e61676504e0a4e527b33b9a0b4495c6872" {
		t.Fatalf("unexpected RNS reference commit %q", fixture.RNSReferenceCommit)
	}
	if !fixture.CanonicalPrivateRoundtrip || !fixture.UnmaskedPrivateRoundtripPreserved || !fixture.UnmaskedAndCanonicalAddressesEqual {
		t.Fatal("fixture does not preserve the required RNS private-key encoding invariants")
	}

	assertFixtureValue(t, "raw candidate input", fixture.RawCandidateInput, hex.EncodeToString(goldenRandomInput(t)))
	assertFixtureValue(t, "X25519 private", fixture.X25519Private, goldenX25519Private)
	assertFixtureValue(t, "X25519 public", fixture.X25519Public, goldenX25519Public)
	assertFixtureValue(t, "Ed25519 seed", fixture.Ed25519Seed, goldenEd25519Seed)
	assertFixtureValue(t, "Ed25519 public", fixture.Ed25519Public, goldenEd25519Public)
	assertFixtureValue(t, "identity hash", fixture.IdentityHash, goldenIdentityHash)
	assertFixtureValue(t, "name hash", fixture.LXMFNameHash, hex.EncodeToString(lxmfNameHash[:]))
	assertFixtureValue(t, "LXMF address", fixture.LXMFAddress, goldenLXMFAddress)
}

func TestReticulumIdentityCorpus(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "rns-identity-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Message     string
		PeerPrivate string `json:"peer_private"`
		Vectors     []struct{ Raw, Private, Public, Hash, Address, Signature, Shared string }
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) != 131 || fixture.Message == "" {
		t.Fatal("incomplete compatibility corpus")
	}
	peer, err := ecdh.X25519().NewPrivateKey(mustDecodeHex(t, fixture.PeerPrivate))
	if err != nil {
		t.Fatal(err)
	}
	for i, vector := range fixture.Vectors {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			raw := mustDecodeHex(t, vector.Raw)
			if len(raw) != identityPrivateKeySize {
				t.Fatal("invalid candidate size")
			}
			var input [64]byte
			copy(input[:], raw)
			var identity Identity
			var public [64]byte
			material := newAddressHashMaterial()
			if err := deriveCandidate(&identity, &input, &public, &material); err != nil {
				t.Fatal(err)
			}
			private := append(append([]byte{}, identity.X25519Private[:]...), identity.Ed25519Seed[:]...)
			assertHexEqual(t, "private", private, vector.Private)
			assertHexEqual(t, "public", public[:], vector.Public)
			assertHexEqual(t, "identity hash", identity.Hash[:], vector.Hash)
			assertHexEqual(t, "destination", identity.Address[:], vector.Address)
			signature := ed25519.Sign(ed25519.NewKeyFromSeed(identity.Ed25519Seed[:]), []byte(fixture.Message))
			assertHexEqual(t, "deterministic signature", signature, vector.Signature)
			if !ed25519.Verify(identity.Ed25519Public[:], []byte(fixture.Message), mustDecodeHex(t, vector.Signature)) {
				t.Fatal("reference signature did not verify")
			}
			key, err := ecdh.X25519().NewPrivateKey(identity.X25519Private[:])
			if err != nil {
				t.Fatal(err)
			}
			shared, err := key.ECDH(peer.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			assertHexEqual(t, "X25519 agreement", shared, vector.Shared)
		})
	}
}

func assertFixtureValue(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s fixture value = %s, want %s", name, got, want)
	}
}

func TestValidateInputsRejectsInvalidWorkerCounts(t *testing.T) {
	originalPrefix, originalPostfix, originalWorkers := prefix, postfix, workers
	originalDryRun, originalPrivateExports := dryRun, includePrivateExports
	originalBenchmark := benchmarkDuration
	t.Cleanup(func() {
		prefix, postfix, workers = originalPrefix, originalPostfix, originalWorkers
		dryRun, includePrivateExports = originalDryRun, originalPrivateExports
		benchmarkDuration = originalBenchmark
	})
	prefix, postfix = "a", ""
	dryRun, includePrivateExports = false, false
	benchmarkDuration = 0

	workers = 0
	if err := validateInputs(); err == nil {
		t.Fatal("expected zero workers to be rejected")
	}
	workers = maxWorkerCount + 1
	if err := validateInputs(); err == nil {
		t.Fatal("expected excessive worker count to be rejected")
	}

	workers = 1
	dryRun, includePrivateExports = true, true
	if err := validateInputs(); err == nil {
		t.Fatal("expected private exports with dry-run to be rejected")
	}
}

func TestValidateInputsForBenchmarkMode(t *testing.T) {
	originalPrefix, originalPostfix, originalWorkers := prefix, postfix, workers
	originalDryRun, originalPrivateExports := dryRun, includePrivateExports
	originalBenchmark := benchmarkDuration
	t.Cleanup(func() {
		prefix, postfix, workers = originalPrefix, originalPostfix, originalWorkers
		dryRun, includePrivateExports = originalDryRun, originalPrivateExports
		benchmarkDuration = originalBenchmark
	})

	prefix, postfix = "", ""
	workers = 1
	dryRun, includePrivateExports = false, false
	benchmarkDuration = time.Second
	if err := validateInputs(); err != nil {
		t.Fatalf("valid benchmark mode rejected: %v", err)
	}

	prefix = "a"
	if err := validateInputs(); err == nil {
		t.Fatal("expected benchmark with a vanity pattern to be rejected")
	}
	prefix = ""
	dryRun = true
	if err := validateInputs(); err == nil {
		t.Fatal("expected benchmark with dry-run to be rejected")
	}
}

func TestPlatformOutputSecurityFailsClosedOnWindows(t *testing.T) {
	if err := validatePlatformOutputSecurity("windows", true, false); err == nil {
		t.Fatal("expected unacknowledged inherited Windows ACL to be rejected")
	}
	if err := validatePlatformOutputSecurity("windows", true, true); err != nil {
		t.Fatalf("explicit inherited Windows ACL acceptance rejected: %v", err)
	}
	if err := validatePlatformOutputSecurity("linux", true, true); err == nil {
		t.Fatal("expected Windows-only override to be rejected on other platforms")
	}
}

func TestAddressMatcherMatchesHexStringSemantics(t *testing.T) {
	addressHex := "abc00000000000000000000000000def"
	address := mustDecodeHex(t, addressHex)

	tests := []struct {
		name    string
		prefix  string
		postfix string
		want    bool
	}{
		{name: "odd both", prefix: "abc", postfix: "def", want: true},
		{name: "uppercase", prefix: "ABC", postfix: "DEF", want: true},
		{name: "one prefix nibble", prefix: "a", want: true},
		{name: "one postfix nibble", postfix: "f", want: true},
		{name: "full address", prefix: addressHex, want: true},
		{name: "even mismatch", prefix: "abd", postfix: "def", want: false},
		{name: "postfix mismatch", prefix: "abc", postfix: "dee", want: false},
		{name: "prefix only", prefix: "abc0", want: true},
		{name: "postfix only", postfix: "0def", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matcher, err := newAddressMatcher(test.prefix, test.postfix)
			if err != nil {
				t.Fatalf("newAddressMatcher failed: %v", err)
			}
			got := matcher.matches(address)
			if got != test.want {
				t.Fatalf("matches = %v, want %v", got, test.want)
			}

			prefixMatch := test.prefix == "" || strings.HasPrefix(addressHex, strings.ToLower(test.prefix))
			postfixMatch := test.postfix == "" || strings.HasSuffix(addressHex, strings.ToLower(test.postfix))
			if got != (prefixMatch && postfixMatch) {
				t.Fatal("byte matcher differs from lowercase hex string semantics")
			}
		})
	}
}

func TestAddressMatcherRejectsInvalidConstruction(t *testing.T) {
	tests := []struct {
		prefix  string
		postfix string
	}{
		{},
		{prefix: "xyz"},
		{prefix: strings.Repeat("a", 33)},
		{postfix: strings.Repeat("b", 33)},
		{prefix: strings.Repeat("a", 16), postfix: strings.Repeat("b", 17)},
	}
	for _, test := range tests {
		if _, err := newAddressMatcher(test.prefix, test.postfix); err == nil {
			t.Fatalf("expected prefix=%q postfix=%q to be rejected", test.prefix, test.postfix)
		}
	}
}

func TestExpectedAttempts(t *testing.T) {
	tests := map[int]string{
		0:  "1",
		1:  "16",
		8:  "4294967296",
		32: "340282366920938463463374607431768211456",
	}
	for characters, want := range tests {
		if got := expectedAttempts(characters); got != want {
			t.Fatalf("expectedAttempts(%d) = %s, want %s", characters, got, want)
		}
	}
	if got := expectedAttempts(33); got != "invalid" {
		t.Fatalf("expected invalid length marker, got %q", got)
	}
}

func TestSearcherReturnsExactlyOneCompatibleResult(t *testing.T) {
	matcher, err := newAddressMatcher(goldenLXMFAddress, "")
	if err != nil {
		t.Fatal(err)
	}
	rng := &repeatingReader{pattern: goldenRandomInput(t)}
	search := newSearcher(matcher, rng)

	identity, err := search.run(context.Background(), 16)
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}
	assertHexEqual(t, "address", identity.Address[:], goldenLXMFAddress)
	if attempts := search.attempts.Load(); attempts < 1 || attempts > 16 {
		t.Fatalf("attempt count %d outside expected winner race range", attempts)
	}
}

func TestEachCandidateConsumesExactly64FreshReaderBytes(t *testing.T) {
	matcher, err := newAddressMatcher(goldenLXMFAddress, "")
	if err != nil {
		t.Fatal(err)
	}
	rng := &countingReader{reader: &repeatingReader{pattern: goldenRandomInput(t)}}
	search := newSearcher(matcher, rng)
	if _, err := search.run(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if got := rng.BytesRead(); got != identityPrivateKeySize {
		t.Fatalf("reader supplied %d bytes for one candidate, want %d", got, identityPrivateKeySize)
	}
}

func TestClampX25519ProducesCanonicalPrivateEncoding(t *testing.T) {
	for first := 0; first <= 0xff; first++ {
		for last := 0; last <= 0xff; last++ {
			var private [32]byte
			private[0] = byte(first)
			private[31] = byte(last)
			clampX25519(&private)
			if private[0]&0x07 != 0 {
				t.Fatalf("low three bits not cleared for first byte %02x", first)
			}
			if private[31]&0x80 != 0 || private[31]&0x40 == 0 {
				t.Fatalf("high-bit mask invalid for last byte %02x: got %02x", last, private[31])
			}
		}
	}
}

func TestSearcherPropagatesRandomSourceFailure(t *testing.T) {
	matcher, err := newAddressMatcher("a", "")
	if err != nil {
		t.Fatal(err)
	}
	search := newSearcher(matcher, errorReader{})
	_, err = search.run(context.Background(), 4)
	if err == nil || !strings.Contains(err.Error(), "secure random source failed") {
		t.Fatalf("expected random-source failure, got %v", err)
	}
}

func TestSearcherHonorsCancellation(t *testing.T) {
	matcher, err := newAddressMatcher("0", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	search := newSearcher(matcher, &repeatingReader{pattern: goldenRandomInput(t)})
	_, err = search.run(ctx, 8)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestSearcherBenchmarkModeRunsUntilDeadline(t *testing.T) {
	search := newSearcher(addressMatcher{}, &repeatingReader{pattern: goldenRandomInput(t)})
	search.stopOnMatch = false
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := search.run(ctx, 1)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected benchmark deadline, got %v", err)
	}
	if attempts := search.attempts.Load(); attempts == 0 {
		t.Fatal("benchmark mode completed no candidate derivations")
	}
}

type readerFunc func([]byte) (int, error)

func (read readerFunc) Read(p []byte) (int, error) { return read(p) }

func TestSearcherCancellationDuringCandidate(t *testing.T) {
	for _, matches := range []bool{false, true} {
		t.Run(fmt.Sprint(matches), func(t *testing.T) {
			pattern := "0"
			if matches {
				pattern = goldenLXMFAddress
			}
			matcher, err := newAddressMatcher(pattern, "")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			raw := goldenRandomInput(t)
			search := newSearcher(matcher, readerFunc(func(p []byte) (int, error) {
				cancel()
				return copy(p, raw), nil
			}))
			identity, err := search.run(ctx, 1)
			if matches {
				if err != nil {
					t.Fatalf("discarded completed winner: %v", err)
				}
				assertHexEqual(t, "address", identity.Address[:], goldenLXMFAddress)
			} else if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation, got %v", err)
			}
			if got := search.attempts.Load(); got != 1 {
				t.Fatalf("completed attempts = %d, want 1", got)
			}
		})
	}
}

func TestAttemptsPerSecondUsesElapsedTime(t *testing.T) {
	if got := attemptsPerSecond(250, 2500*time.Millisecond); got != 100 {
		t.Fatalf("rate = %d, want 100", got)
	}
	if got := attemptsPerSecond(0, 0); got != 0 {
		t.Fatalf("empty sample rate = %d", got)
	}
}

func TestSaveIdentityDefaultMetadataContainsNoPrivateExports(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")
	identity := goldenIdentity(t)

	if err := testOutput(t, path).saveIdentity(&identity, false); err != nil {
		t.Fatalf("saveIdentity failed: %v", err)
	}

	privateFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wantPrivate := append(mustDecodeHex(t, goldenX25519Private), mustDecodeHex(t, goldenEd25519Seed)...)
	if !bytes.Equal(privateFile, wantPrivate) {
		t.Fatalf("private identity bytes differ\ngot  %x\nwant %x", privateFile, wantPrivate)
	}

	metadata, err := os.ReadFile(path + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	metadataText := string(metadata)
	if !strings.Contains(metadataText, "This metadata file contains public information only.") {
		t.Fatal("metadata is not clearly labelled public-only")
	}
	if !strings.Contains(metadataText, "<lxmf.delivery."+goldenIdentityHash+":"+goldenLXMFAddress+">") {
		t.Fatal("metadata missing canonical full specifier")
	}
	if strings.Contains(metadataText, base64.URLEncoding.EncodeToString(wantPrivate)) {
		t.Fatal("default metadata leaked Base64 private identity")
	}
	if strings.Contains(metadataText, base32.StdEncoding.EncodeToString(wantPrivate)) {
		t.Fatal("default metadata leaked Base32 private identity")
	}

	if runtime.GOOS != "windows" {
		if mode := mustPerm(t, path); mode != 0o600 {
			t.Fatalf("identity mode = %03o, want 600", mode)
		}
		if mode := mustPerm(t, path+".txt"); mode != 0o600 {
			t.Fatalf("metadata mode = %03o, want 600", mode)
		}
	}
}

func TestSaveIdentityPrivateExportsRequireExplicitOptIn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")
	identity := goldenIdentity(t)

	if err := testOutput(t, path).saveIdentity(&identity, true); err != nil {
		t.Fatalf("saveIdentity failed: %v", err)
	}
	metadata, err := os.ReadFile(path + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	wantPrivate := append(mustDecodeHex(t, goldenX25519Private), mustDecodeHex(t, goldenEd25519Seed)...)
	metadataText := string(metadata)
	if !strings.Contains(metadataText, "WARNING: Reversible private identity exports follow") {
		t.Fatal("private export metadata is not clearly warned")
	}
	if strings.Contains(metadataText, "contains public information only") {
		t.Fatal("private export metadata was incorrectly labelled public-only")
	}
	if !strings.Contains(metadataText, base64.URLEncoding.EncodeToString(wantPrivate)) {
		t.Fatal("opt-in metadata missing Base64 private identity")
	}
	if !strings.Contains(metadataText, base32.StdEncoding.EncodeToString(wantPrivate)) {
		t.Fatal("opt-in metadata missing Base32 private identity")
	}
}

func TestSaveIdentityRejectsInconsistentDerivedFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")
	identity := goldenIdentity(t)
	identity.Address[0] ^= 0xff

	if err := testOutput(t, path).saveIdentity(&identity, false); err == nil {
		t.Fatal("expected inconsistent identity to be rejected")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("inconsistent identity unexpectedly created output: %v", err)
	}
}

func TestSaveIdentityPreservesWinnerAfterLateCollision(t *testing.T) {
	for _, suffix := range []string{"", ".txt"} {
		t.Run("collision"+suffix, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identity")
			if err := testOutput(t, path).preflight(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+suffix, []byte("existing"), 0o600); err != nil {
				t.Fatal(err)
			}
			identity := goldenIdentity(t)
			err := testOutput(t, path).saveIdentity(&identity, false)
			if err == nil {
				t.Fatal("expected collision error")
			}
			var recovery *recoverableWriteError
			savedPath := path
			if suffix == "" {
				if !errors.As(err, &recovery) {
					t.Fatalf("expected recoverable identity: %v", err)
				}
				savedPath = recovery.recoveryPath
			} else if !strings.Contains(err.Error(), "identity was saved") {
				t.Fatalf("expected explicit partial success: %v", err)
			}
			data, readErr := os.ReadFile(savedPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			assertHexEqual(t, "saved private key", data, goldenX25519Private+goldenEd25519Seed)
			original, readErr := os.ReadFile(path + suffix)
			if readErr != nil || string(original) != "existing" {
				t.Fatalf("collision target changed: %v", readErr)
			}
		})
	}
}

func TestValidateOutputTargetRejectsExistingOutputBeforeSearch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := testOutput(t, path).preflight(); err == nil {
		t.Fatal("expected existing output path to be rejected")
	}
}

func TestWriteFileSafelyRefusesExistingTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	output := testOutput(t, path)

	if err := output.writeFile(output.name, []byte("first"), 0o600, output.root.Link, false); err != nil {
		t.Fatalf("initial write failed: %v", err)
	}
	if err := output.writeFile(output.name, []byte("second"), 0o600, output.root.Link, false); err == nil {
		t.Fatal("expected overwrite refusal")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first" {
		t.Fatalf("target was overwritten: %q", data)
	}
}

func TestWriteFileSafelyFallsBackWhenHardLinksAreUnavailable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	output := testOutput(t, path)
	linkUnavailable := func(string, string) error {
		return errors.New("hard links unavailable")
	}

	if err := output.writeFile(output.name, []byte("identity"), 0o600, linkUnavailable, false); err != nil {
		t.Fatalf("exclusive fallback failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "identity" {
		t.Fatalf("fallback content = %q", data)
	}
	if err := output.writeFile(output.name, []byte("replacement"), 0o600, linkUnavailable, false); err == nil {
		t.Fatal("fallback overwrote an existing target")
	}
}

func TestRecoverableIdentityWriteRetainsCompleteTempOnPublicationRace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")
	output := testOutput(t, path)
	secret := []byte("complete private identity material")
	publicationRace := func(_, target string) error {
		if err := os.WriteFile(filepath.Join(dir, target), []byte("racer"), 0o600); err != nil {
			t.Fatal(err)
		}
		return errors.New("injected publication race")
	}

	err := output.writeFile(output.name, secret, 0o600, publicationRace, true)
	var recoveryErr *recoverableWriteError
	if !errors.As(err, &recoveryErr) {
		t.Fatalf("expected recoverable write error, got %v", err)
	}
	recovered, readErr := os.ReadFile(recoveryErr.recoveryPath)
	if readErr != nil {
		t.Fatalf("read recovery file: %v", readErr)
	}
	if !bytes.Equal(recovered, secret) {
		t.Fatalf("recovery file = %q, want %q", recovered, secret)
	}
	if runtime.GOOS != "windows" && mustPerm(t, recoveryErr.recoveryPath) != 0o600 {
		t.Fatal("recovery file permissions are not 0600")
	}
}

func TestEnsureDoesNotExistRejectsDanglingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require additional Windows privileges")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")
	if err := os.Symlink(filepath.Join(dir, "missing"), path); err != nil {
		t.Fatal(err)
	}
	if err := testOutput(t, path).ensureDoesNotExist(filepath.Base(path)); err == nil {
		t.Fatal("expected dangling symlink target to be rejected")
	}
}

func BenchmarkDeriveCandidate(b *testing.B) {
	var identity Identity
	var randBuf [identityPrivateKeySize]byte
	var publicKey [64]byte
	addrHashMaterial := newAddressHashMaterial()
	copy(randBuf[:], goldenRandomInput(b))

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		randBuf[1] = byte(i)
		if err := deriveCandidate(&identity, &randBuf, &publicKey, &addrHashMaterial); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddressMatcher(b *testing.B) {
	matcher, err := newAddressMatcher("cafebabe", "deadbeef")
	if err != nil {
		b.Fatal(err)
	}
	address := mustDecodeHex(b, "cafebabe0000000000000000deadbeef")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !matcher.matches(address) {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkSecureCandidate(b *testing.B) {
	var identity Identity
	var input [identityPrivateKeySize]byte
	var publicKey [64]byte
	material := newAddressHashMaterial()
	defer wipeIdentitySecrets(&identity)
	defer wipeBytes(input[:])
	b.ReportAllocs()
	for b.Loop() {
		if _, err := io.ReadFull(rand.Reader, input[:]); err != nil {
			b.Fatal(err)
		}
		if err := deriveCandidate(&identity, &input, &publicKey, &material); err != nil {
			b.Fatal(err)
		}
	}
}

func goldenIdentity(tb testing.TB) Identity {
	tb.Helper()
	input := goldenRandomInput(tb)
	var randBuf [identityPrivateKeySize]byte
	copy(randBuf[:], input)
	var identity Identity
	var publicKey [64]byte
	material := newAddressHashMaterial()
	if err := deriveCandidate(&identity, &randBuf, &publicKey, &material); err != nil {
		tb.Fatalf("derive candidate: %v", err)
	}
	return identity
}

func FuzzAddressMatcher(f *testing.F) {
	f.Add(mustDecodeHex(f, "abc00000000000000000000000000def"), "abc", "def")
	f.Add(mustDecodeHex(f, goldenLXMFAddress), goldenLXMFAddress, "")
	f.Add(make([]byte, addressByteLength), "A", "0")
	for split := 0; split <= addressHexLength; split++ {
		f.Add(mustDecodeHex(f, goldenLXMFAddress), strings.ToUpper(goldenLXMFAddress[:split]), goldenLXMFAddress[split:])
	}
	f.Add([]byte{}, "a", "")
	f.Add(make([]byte, addressByteLength+1), "0", "")

	f.Fuzz(func(t *testing.T, address []byte, candidatePrefix, candidatePostfix string) {
		matcher, err := newAddressMatcher(candidatePrefix, candidatePostfix)
		if err != nil {
			return
		}
		addressHex := hex.EncodeToString(address)
		want := len(address) == addressByteLength && strings.HasPrefix(addressHex, strings.ToLower(candidatePrefix)) &&
			strings.HasSuffix(addressHex, strings.ToLower(candidatePostfix))
		if got := matcher.matches(address); got != want {
			t.Fatalf("matcher divergence: address=%s prefix=%q postfix=%q got=%v want=%v", addressHex, candidatePrefix, candidatePostfix, got, want)
		}
	})
}

func goldenRandomInput(tb testing.TB) []byte {
	tb.Helper()
	// Start from the reference private identity, then deliberately restore bits
	// that RFC 7748 masking must clear. This makes the vector test persistence
	// of the masked key, not only public-key derivation (which masks internally).
	x25519Input := mustDecodeHex(tb, goldenX25519Private)
	x25519Input[0] |= 0x07
	x25519Input[31] |= 0x80
	input := append(x25519Input, mustDecodeHex(tb, goldenEd25519Seed)...)
	if len(input) != identityPrivateKeySize {
		tb.Fatalf("golden input length = %d", len(input))
	}
	return input
}

func assertHexEqual(tb testing.TB, name string, got []byte, want string) {
	tb.Helper()
	if hex.EncodeToString(got) != want {
		tb.Fatalf("%s = %x, want %s", name, got, want)
	}
}

func mustDecodeHex(tb testing.TB, value string) []byte {
	tb.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		tb.Fatalf("decode %q: %v", value, err)
	}
	return decoded
}

func mustPerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

type repeatingReader struct {
	mu      sync.Mutex
	pattern []byte
}

func (r *repeatingReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pattern) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	for i := range p {
		p[i] = r.pattern[i%len(r.pattern)]
	}
	return len(p), nil
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("injected random failure")
}

type countingReader struct {
	mu     sync.Mutex
	reader io.Reader
	read   uint64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.mu.Lock()
	r.read += uint64(n)
	r.mu.Unlock()
	return n, err
}

func (r *countingReader) BytesRead() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.read
}

func testOutput(t *testing.T, path string) *outputTarget {
	t.Helper()
	output, err := openOutputTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { output.root.Close() })
	return output
}

func TestOutputDirectoryReplacementCannotRedirectIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("open directory handles may prohibit renaming on Windows")
	}
	for _, fallback := range []bool{false, true} {
		t.Run(fmt.Sprint("fallback=", fallback), func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, "output")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			output := testOutput(t, filepath.Join(dir, "identity"))
			if err := output.preflight(); err != nil {
				t.Fatal(err)
			}
			moved := filepath.Join(parent, "moved")
			if err := os.Rename(dir, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			link := output.root.Link
			if fallback {
				link = func(string, string) error { return errors.New("no hard links") }
			}
			if err := output.writeFile(output.name, []byte("private data"), 0600, link, true); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(moved, "identity"))
			if err != nil || string(got) != "private data" {
				t.Fatalf("anchored output missing: %v", err)
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 0 {
				t.Fatalf("replacement directory modified: %v", err)
			}
			if output.checkLocation() == nil {
				t.Fatal("directory replacement was not reported")
			}
		})
	}
}
