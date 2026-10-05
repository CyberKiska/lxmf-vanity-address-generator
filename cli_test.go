package main

import (
	"bytes"
	"context"
	"io"
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
			if os.Getenv("LXMF_VANITY_TEST_NONMATCH") == "1" {
				cfg, err := parseArgs(os.Args[1:], io.Discard)
				if err != nil {
					t.Fatal(err)
				}
				code := runWithDependencies(context.Background(), cfg, os.Stdout, os.Stderr, runDependencies{rng: &repeatingReader{pattern: goldenRandomInput(t)}})
				os.Exit(code)
			}
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

func TestCLIHelpDoesNotCreateFiles(t *testing.T) {
	dir := t.TempDir()
	output, err := runCLI(t, dir, "--help")
	if err != nil || !strings.Contains(string(output), "include-private-exports") {
		t.Fatalf("help: %v: %s", err, output)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("help created files: %v", err)
	}
}

func TestCLIExitCodesAndStreams(t *testing.T) {
	for _, test := range []struct {
		args []string
		want int
	}{
		{[]string{"--prefix", "f", "--workers", "1", "--dry-run"}, 0},
		{[]string{"--prefix", "f", "--out", "missing-directory/saved"}, 1},
		{[]string{"--prefix", "bad-pattern"}, 2},
		{[]string{"--prefix", strings.Repeat("0", 32), "--workers", "1", "--dry-run", "--max-attempts", "1"}, 4},
	} {
		output, err := runCLI(t, t.TempDir(), test.args...)
		code := 0
		if err != nil {
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal(err)
			}
			code = exit.ExitCode()
		}
		if code != test.want {
			t.Fatalf("args %v: exit %d want %d: %s", test.args, code, test.want, output)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIProcess$", "--", "--prefix", "f", "--workers", "1", "--dry-run")
	cmd.Env = append(os.Environ(), "LXMF_VANITY_TEST_PROCESS=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "search started") || !strings.Contains(stderr.String(), "search started") || !strings.Contains(stdout.String(), "Found matching address") {
		t.Fatal("stream contract changed")
	}
}
