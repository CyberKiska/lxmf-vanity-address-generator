package main

import (
	"io"
	"strings"
	"testing"
)

func TestVersionBypassesSearchAndProviderValidation(t *testing.T) {
	cfg, err := parseArgs([]string{"--version", "--prefix", "invalid"}, io.Discard)
	if err != nil || !cfg.showVersion {
		t.Fatal("version validated search flags")
	}
	output, err := runCLI(t, t.TempDir(), "--version")
	if err != nil || !strings.Contains(string(output), "lxmf-vanity") || !strings.Contains(string(output), "go1.") {
		t.Fatalf("version %v: %s", err, output)
	}
}
