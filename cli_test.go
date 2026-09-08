package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Run the real CLI in a subprocess so flag parsing and exit behavior are tested
// without sharing mutable flags with other tests.
func TestCLIProcess(t *testing.T) {
	if os.Getenv("LXMF_VANITY_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	t.Fatal("missing CLI argument separator")
}

func runCLI(t *testing.T, dir string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestCLIProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "LXMF_VANITY_TEST_PROCESS=1")
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("CLI timed out: %s", output)
	}
	return output, err
}

func TestCLIRejectsTrailingArgumentsBeforeCreatingFiles(t *testing.T) {
	for _, args := range [][]string{
		{"--prefix", "a", "unexpected", "--dry-run"},
		{"--prefix", "a", "unexpected", "--out", "elsewhere"},
		{"--benchmark", "1ms", "unexpected"},
	} {
		dir := t.TempDir()
		output, err := runCLI(t, dir, args...)
		if err == nil || !strings.Contains(string(output), "unexpected positional arguments") {
			t.Fatalf("args %q: expected rejection, got %v: %s", args, err, output)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("rejected CLI created files: %v (%v)", entries, err)
		}
	}
}

func TestCLIDryRunCreatesNoFiles(t *testing.T) {
	dir := t.TempDir()
	output, err := runCLI(t, dir, "--prefix", "A", "--postfix", "B", "--workers", "2", "--dry-run")
	if err != nil || !strings.Contains(string(output), "Found matching address: a") {
		t.Fatalf("dry run failed: %v: %s", err, output)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("dry run created files: %v (%v)", entries, err)
	}
}

func TestCLIBenchmarkReportsElapsedTimeWithoutFiles(t *testing.T) {
	dir := t.TempDir()
	output, err := runCLI(t, dir, "--benchmark", "20ms", "--workers", "1")
	if err != nil || !strings.Contains(string(output), " attempts in ") || !strings.Contains(string(output), "/s average)") {
		t.Fatalf("benchmark failed: %v: %s", err, output)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("benchmark created files: %v (%v)", entries, err)
	}
}
