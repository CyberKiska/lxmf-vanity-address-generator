package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestJSONPublicResultModes(t *testing.T) {
	for _, mode := range []string{"saved", "dry-run", "limited", "benchmark", "failed"} {
		path := filepath.Join(t.TempDir(), "saved")
		args := []string{"--json", "--workers", "1"}
		switch mode {
		case "benchmark":
			args = append(args, "--benchmark", "1ms")
		case "limited":
			args = append(args, "--prefix", "0", "--dry-run", "--max-attempts", "1", "--generator", "independent")
		default:
			args = append(args, "--prefix", goldenLXMFAddress, "--out", path)
		}
		if mode == "dry-run" {
			args = append(args, "--dry-run")
		}
		if os.PathSeparator == '\\' && mode == "saved" {
			args = append(args, "--allow-weak-output-protection")
		}
		cfg, err := parseArgs(args, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		reader := io.Reader(&repeatingReader{pattern: goldenRandomInput(t)})
		if mode == "failed" {
			reader = errorReader{}
			cfg.dryRun = true
		}
		code := runWithDependencies(context.Background(), cfg, &output, io.Discard, runDependencies{rng: reader, signals: make(chan os.Signal)})
		var result publicResult
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatalf("JSON %s code %d: %s", mode, code, output.String())
		}
		if result.Status != mode && !(mode == "saved" && result.Status == "partial") {
			t.Fatalf("status %s want %s", result.Status, mode)
		}
		if strings.Count(output.String(), "\n") != 1 || strings.Contains(output.String(), goldenEd25519Seed) || strings.Contains(output.String(), goldenX25519Private) {
			t.Fatal("stdout is not one public JSON object")
		}
		if mode == "saved" && (result.Address != goldenLXMFAddress || result.IdentityHash != goldenIdentityHash || result.PublicKey != goldenX25519Public+goldenEd25519Public) {
			t.Fatal("JSON public fields differ from sidecar contract")
		}
	}
}

type recoveryDiscardWriter struct {
	input chan os.Signal
	once  sync.Once
}

func (w *recoveryDiscardWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("Save recovery:")) {
		w.once.Do(func() {
			w.input <- os.Interrupt
			w.input <- os.Interrupt
		})
	}
	return len(p), nil
}

func TestJSONExplicitDiscardReportsUnverifiedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "saved")
	cfg, err := parseArgs([]string{"--json", "--prefix", goldenLXMFAddress, "--workers", "1", "--out", path, "--save-retry-timeout", "5s"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	cfg.allowWeakOutput = true // Includes Windows' explicit ACL acknowledgement.
	input := make(chan os.Signal, 2)
	stderr := &recoveryDiscardWriter{input: input}
	var faults *faultDir
	raw := goldenRandomInput(t)
	var stdout bytes.Buffer
	code := runWithDependencies(context.Background(), cfg, &stdout, stderr, runDependencies{
		signals: input,
		openTarget: func(name string) (*outputTarget, error) {
			out, err := openOutputTarget(name)
			if err == nil {
				faults = &faultDir{dirOps: out.root}
				out.root = faults
			}
			return out, err
		},
		rng: readerFunc(func(p []byte) (int, error) {
			// Preflight has completed. Retain a full file whose sync fails.
			faults.rules = []faultRule{{op: "sync", err: errors.New("injected sync failure")}}
			return copy(p, raw), nil
		}),
		consoleTimeout: time.Second,
	})
	var result publicResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if code != 130 || result.Status != "cancelled" || len(result.VerifiedFiles) != 0 || len(result.UnverifiedFiles) != 1 {
		t.Fatalf("discard outcome: code=%d result=%+v", code, result)
	}
	if !strings.Contains(result.Error, "explicitly abandoned") || len(result.Deviations) == 0 {
		t.Fatal("discard cause or retained-file warnings omitted")
	}
	if info, err := os.Stat(result.UnverifiedFiles[0]); err != nil || info.Size() != 64 {
		t.Fatal("unverified file was lost or not reported")
	}
}
func TestJSONInspectionAndVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disposable")
	os.WriteFile(path, goldenRandomInput(t), 0600)
	for _, args := range [][]string{{"--json", "--inspect", path}, {"--json", "--version"}} {
		cfg, err := parseArgs(args, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), cfg, &stdout, &stderr); code != 0 {
			t.Fatal("public query failed")
		}
		var result publicResult
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if cfg.inspectPath != "" && result.Address != goldenLXMFAddress {
			t.Fatal("inspection JSON mismatch")
		}
	}
}

func TestJSONIncludesPreflightAndSaveProtectionNotices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "saved")
	cfg, err := parseArgs([]string{"--json", "--prefix", goldenLXMFAddress, "--workers", "1", "--out", path, "--allow-weak-output-protection"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var target *outputTarget
	var stdout bytes.Buffer
	raw := goldenRandomInput(t)
	code := runWithDependencies(context.Background(), cfg, &stdout, io.Discard, runDependencies{
		signals: make(chan os.Signal),
		openTarget: func(name string) (*outputTarget, error) {
			var err error
			target, err = openOutputTarget(name)
			if err == nil {
				target.allowWeak = true
				target.protection(errors.New("preflight protection unavailable"))
			}
			return target, err
		},
		rng: readerFunc(func(p []byte) (int, error) {
			// This notice occurs after the preflight console output.
			target.protection(errors.New("save protection unavailable"))
			return copy(p, raw), nil
		}),
	})
	var result publicResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if code != 0 || result.Status != "saved" {
		t.Fatalf("unexpected save result: code=%d result=%+v", code, result)
	}
	for _, reason := range []string{"preflight protection unavailable", "save protection unavailable"} {
		if !strings.Contains(strings.Join(result.Notices, "\n"), reason) {
			t.Fatalf("missing protection notice %q: %q", reason, result.Notices)
		}
	}
}
