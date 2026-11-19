//go:build unix

package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCLISignalsCancelAfterReadiness(t *testing.T) {
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIProcess$", "--", "--prefix", strings.Repeat("0", 32), "--workers", "1", "--out", filepath.Join(dir, "saved"))
			cmd.Env = append(os.Environ(), "LXMF_VANITY_TEST_PROCESS=1", "LXMF_VANITY_TEST_NONMATCH=1")
			cmd.Dir = dir
			stderr, err := cmd.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			cmd.Stdout = &stdout
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			ready := false
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				if scanner.Text() == "search started" {
					ready = true
					break
				}
			}
			if !ready {
				t.Fatal("no readiness marker")
			}
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, stderr)
			err = cmd.Wait()
			var exit *exec.ExitError
			if err == nil || !errorsAsExit(err, &exit) || exit.ExitCode() != 130 {
				t.Fatalf("signal exit %v: %s", err, stdout.String())
			}
			files, _ := os.ReadDir(dir)
			if len(files) != 0 {
				t.Fatal("cancelled nonmatching search wrote identity")
			}
		})
	}
}
func errorsAsExit(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}
func TestClosedPipesSaveBeforeReportingDeliveryFailure(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIProcess$", "--", "--prefix", "f", "--workers", "1", "--out", filepath.Join(dir, "saved"))
	cmd.Env = append(os.Environ(), "LXMF_VANITY_TEST_PROCESS=1")
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	read.Close()
	defer write.Close()
	cmd.Stdout, cmd.Stderr = write, write
	err = cmd.Run()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 3 {
		t.Fatalf("closed pipe killed process or lost delivery status: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "saved"))
	if err != nil || len(data) != 64 {
		t.Fatal("closed pipes lost winner")
	}
}

func TestRunReportsVerifiedIdentityInMovedDirectory(t *testing.T) {
	parent := t.TempDir()
	directory := filepath.Join(parent, "opened")
	moved := filepath.Join(parent, "moved")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseArgs([]string{"--prefix", goldenLXMFAddress, "--workers", "1", "--out", filepath.Join(directory, "saved"), "--json"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	raw := goldenRandomInput(t)
	code := runWithDependencies(context.Background(), cfg, &stdout, io.Discard, runDependencies{signals: make(chan os.Signal), rng: readerFunc(func(p []byte) (int, error) {
		if err := os.Rename(directory, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		return copy(p, raw), nil
	})})
	if code != 3 || !strings.Contains(stdout.String(), goldenLXMFAddress) || !strings.Contains(stdout.String(), "originally opened directory") {
		t.Fatalf("moved save status %d: %s", code, stdout.String())
	}
	data, err := os.ReadFile(filepath.Join(moved, "saved"))
	if err != nil {
		t.Fatal(err)
	}
	assertHexEqual(t, "moved identity", data, goldenX25519Private+goldenEd25519Seed)
	entries, _ := os.ReadDir(directory)
	if len(entries) != 0 {
		t.Fatal("replacement received identity bytes")
	}
}
