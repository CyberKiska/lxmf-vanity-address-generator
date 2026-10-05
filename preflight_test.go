package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPreflightExercisesPublicationOperations(t *testing.T) {
	for _, op := range []string{"open", "chmod", "write", "sync", "close", "read", "remove"} {
		t.Run(op, func(t *testing.T) {
			out := testOutput(t, filepath.Join(t.TempDir(), "saved"))
			out.root = &faultDir{dirOps: out.root, rules: []faultRule{{op: op, nth: 1, err: errors.New("injected " + op)}}}
			err := out.preflight()
			if err == nil {
				t.Fatal("preflight accepted operation failure")
			}
			entries, _ := os.ReadDir(filepath.Dir(out.path))
			if op == "remove" && (len(entries) != 1 || !strings.Contains(err.Error(), entries[0].Name())) {
				t.Fatal("remaining probe not reported")
			}
			if op != "remove" && len(entries) != 0 {
				t.Fatalf("probes left after %s: %v", op, entries)
			}
		})
	}
	for _, failFallback := range []bool{false, true} {
		out := testOutput(t, filepath.Join(t.TempDir(), "saved"))
		fault := &faultDir{dirOps: out.root, link: func(string, string) error { return syscall.ENOTSUP }}
		if failFallback {
			fault.rules = []faultRule{{op: "write", nth: 2, err: syscall.ENOSPC}}
		}
		out.root = fault
		err := out.preflight()
		if (err != nil) != failFallback || !out.exclusive {
			t.Fatalf("fallback preflight: %v", err)
		}
	}
}
func TestSaveFaultStatesAreBoundedAndTruthful(t *testing.T) {
	for _, rule := range []faultRule{
		{op: "open", nth: 1, err: syscall.ENOSPC},
		{op: "chmod", nth: 1, err: syscall.EPERM},
		{op: "write", nth: 1, short: 16, err: nil},
		{op: "write", nth: 1, after: true, err: syscall.ENOSPC},
		{op: "read", nth: 1, err: syscall.EIO},
		{op: "sync", nth: 0, err: syscall.EIO},
		{op: "remove", nth: 1, err: syscall.EPERM},
	} {
		t.Run(rule.op, func(t *testing.T) {
			out := testOutput(t, filepath.Join(t.TempDir(), "saved"))
			fault := &faultDir{dirOps: out.root, rules: []faultRule{rule}}
			out.root = fault
			identity := goldenIdentity(t)
			for range 4 {
				result := out.saveIdentity(&identity, addressMatcher{}, false)
				entries, _ := os.ReadDir(filepath.Dir(out.path))
				if len(entries) > 3 {
					t.Fatalf("unbounded retained files: %d", len(entries))
				}
				for _, path := range result.Verified {
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					assertHexEqual(t, "verified copy", data, goldenX25519Private+goldenEd25519Seed)
				}
				if result.saved() {
					break
				}
			}
		})
	}
}
func TestOutputPathSeparators(t *testing.T) {
	for _, path := range []string{"", "dir/"} {
		if _, err := openOutputTarget(path); err == nil {
			t.Fatal("directory syntax accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "file\\")
	if os.IsPathSeparator('\\') {
		if _, err := openOutputTarget(path); err == nil {
			t.Fatal("Windows trailing separator accepted")
		}
	} else {
		testOutput(t, path)
	}
}
