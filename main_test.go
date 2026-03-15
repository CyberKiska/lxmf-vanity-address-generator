package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateInputsRejectsCombinedLengthOver32(t *testing.T) {
	origPrefix, origPostfix, origWorkers := prefix, postfix, workers
	t.Cleanup(func() {
		prefix = origPrefix
		postfix = origPostfix
		workers = origWorkers
	})

	prefix = "aaaaaaaaaaaaaaaa"
	postfix = "bbbbbbbbbbbbbbbbb"
	workers = 1

	err := validateInputs()
	if err == nil || !strings.Contains(err.Error(), "combined prefix and postfix length") {
		t.Fatalf("expected combined-length validation error, got %v", err)
	}
}

func TestMatchesPatternUsesExactNibbleSemantics(t *testing.T) {
	origPrefixNibbles, origPostfixNibbles := prefixNibbles, postfixNibbles
	t.Cleanup(func() {
		prefixNibbles = origPrefixNibbles
		postfixNibbles = origPostfixNibbles
	})

	addr, err := hex.DecodeString("abc00000000000000000000000000def")
	if err != nil {
		t.Fatalf("failed to decode test address: %v", err)
	}

	prefixNibbles = hexToNibbles("abc")
	postfixNibbles = hexToNibbles("def")
	if !matchesPattern(addr) {
		t.Fatal("expected address to match odd-length prefix and postfix")
	}

	postfixNibbles = hexToNibbles("dee")
	if matchesPattern(addr) {
		t.Fatal("expected postfix mismatch to fail")
	}
}

func TestSaveIdentityWritesSecureCompatibleFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")

	identity := &Identity{}
	for i := 0; i < 32; i++ {
		identity.X25519Private[i] = byte(i)
		identity.X25519Public[i] = byte(i + 32)
		identity.Ed25519Seed[i] = byte(i + 64)
		identity.Ed25519Public[i] = byte(i + 96)
	}
	for i := 0; i < 16; i++ {
		identity.Hash[i] = byte(i + 128)
		identity.Address[i] = byte(i + 144)
	}

	if err := saveIdentity(identity, path); err != nil {
		t.Fatalf("saveIdentity failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read identity file: %v", err)
	}
	if len(data) != 64 {
		t.Fatalf("expected 64-byte identity file, got %d", len(data))
	}

	info, err := os.ReadFile(path + ".txt")
	if err != nil {
		t.Fatalf("failed to read info file: %v", err)
	}

	if strings.Contains(string(info), hex.EncodeToString(identity.X25519Private[:])) {
		t.Fatal("info file should not leak raw X25519 private key hex")
	}
	if strings.Contains(string(info), hex.EncodeToString(identity.Ed25519Seed[:])) {
		t.Fatal("info file should not leak raw Ed25519 seed hex")
	}

	if mode := mustPerm(t, path); mode != 0o600 {
		t.Fatalf("expected identity file mode 0600, got %03o", mode)
	}
	if mode := mustPerm(t, path+".txt"); mode != 0o600 {
		t.Fatalf("expected info file mode 0600, got %03o", mode)
	}

	if err := saveIdentity(identity, path); err == nil {
		t.Fatal("expected overwrite refusal when saving to an existing path")
	}

	var privKey [64]byte
	copy(privKey[0:32], identity.X25519Private[:])
	copy(privKey[32:64], identity.Ed25519Seed[:])

	infoText := string(info)
	if want := base64.URLEncoding.EncodeToString(privKey[:]); !strings.Contains(infoText, want) {
		t.Fatal("info file missing urlsafe base64 import string")
	}
	if want := base32.StdEncoding.EncodeToString(privKey[:]); !strings.Contains(infoText, want) {
		t.Fatal("info file missing base32 import string")
	}
}

func TestValidateOutputTargetRejectsExistingOutputBeforeSearch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatalf("failed to seed existing file: %v", err)
	}

	if err := validateOutputTarget(path); err == nil {
		t.Fatal("expected existing output path to be rejected")
	}
}

func mustPerm(t *testing.T, path string) os.FileMode {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s failed: %v", path, err)
	}

	return info.Mode().Perm()
}
