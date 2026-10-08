package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
