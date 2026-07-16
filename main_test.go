package main

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const (
	goldenX25519Private = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e5f"
	goldenX25519Public  = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
	goldenEd25519Seed   = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	goldenEd25519Public = "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"
	goldenIdentityHash  = "aca31af0441d81dbec71e82da0b4b5f5"
	goldenLXMFAddress   = "fae321c442e3c9bdcd7a3e79d850e03c"
)

// These values were generated with Reticulum 1.3.8 at commit
// de0f399a1696895dcb95ad1efa19f3b21a7886ab and are intentionally fixed.
func TestDeriveCandidateMatchesReticulum138GoldenVector(t *testing.T) {
	identity := goldenIdentity(t)

	assertHexEqual(t, "X25519 private", identity.X25519Private[:], goldenX25519Private)
	assertHexEqual(t, "X25519 public", identity.X25519Public[:], goldenX25519Public)
	assertHexEqual(t, "Ed25519 seed", identity.Ed25519Seed[:], goldenEd25519Seed)
	assertHexEqual(t, "Ed25519 public", identity.Ed25519Public[:], goldenEd25519Public)
	assertHexEqual(t, "identity hash", identity.Hash[:], goldenIdentityHash)
	assertHexEqual(t, "LXMF address", identity.Address[:], goldenLXMFAddress)
}

func TestValidateInputsRejectsInvalidWorkerCounts(t *testing.T) {
	originalPrefix, originalPostfix, originalWorkers := prefix, postfix, workers
	originalDryRun, originalPrivateExports := dryRun, includePrivateExports
	t.Cleanup(func() {
		prefix, postfix, workers = originalPrefix, originalPostfix, originalWorkers
		dryRun, includePrivateExports = originalDryRun, originalPrivateExports
	})
	prefix, postfix = "a", ""
	dryRun, includePrivateExports = false, false

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

func TestSaveIdentityDefaultMetadataContainsNoPrivateExports(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")
	identity := goldenIdentity(t)

	if err := saveIdentity(&identity, path, false); err != nil {
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

	if err := saveIdentity(&identity, path, true); err != nil {
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

func TestValidateOutputTargetRejectsExistingOutputBeforeSearch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := preflightOutputTarget(path); err == nil {
		t.Fatal("expected existing output path to be rejected")
	}
}

func TestWriteFileSafelyRefusesExistingTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")

	if err := writeFileSafely(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("initial write failed: %v", err)
	}
	if err := writeFileSafely(path, []byte("second"), 0o600); err == nil {
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
	linkUnavailable := func(string, string) error {
		return errors.New("hard links unavailable")
	}

	if err := writeFileSafelyWithLink(path, []byte("identity"), 0o600, linkUnavailable); err != nil {
		t.Fatalf("exclusive fallback failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "identity" {
		t.Fatalf("fallback content = %q", data)
	}
	if err := writeFileSafelyWithLink(path, []byte("replacement"), 0o600, linkUnavailable); err == nil {
		t.Fatal("fallback overwrote an existing target")
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
	if err := ensureDoesNotExist(path); err == nil {
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
		deriveCandidate(&identity, &randBuf, &publicKey, &addrHashMaterial)
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

func goldenIdentity(tb testing.TB) Identity {
	tb.Helper()
	input := goldenRandomInput(tb)
	var randBuf [identityPrivateKeySize]byte
	copy(randBuf[:], input)
	var identity Identity
	var publicKey [64]byte
	material := newAddressHashMaterial()
	deriveCandidate(&identity, &randBuf, &publicKey, &material)
	return identity
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
