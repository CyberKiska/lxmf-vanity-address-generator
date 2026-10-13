package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSidecarOmitsAbsolutePrivateLocation(t *testing.T) {
	out := testOutput(t, filepath.Join(t.TempDir(), "public-name"))
	identity := goldenIdentity(t)
	result := out.saveIdentity(&identity, addressMatcher{}, false)
	if !result.saved() {
		t.Fatal(result.cause)
	}
	data, err := os.ReadFile(out.path + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), filepath.Dir(out.path)) || !strings.Contains(string(data), `Private identity file: "public-name"`) {
		t.Fatal("sidecar discloses private directory or loses quoted basename")
	}
}
