package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveRejectsConsistentNonmatchingCandidate(t *testing.T) {
	identity := goldenIdentity(t)
	out := testOutput(t, filepath.Join(t.TempDir(), "saved"))
	matcher, _ := newAddressMatcher("0", "")
	result := out.saveIdentity(&identity, matcher, false)
	if !result.internal || len(result.Verified) != 0 {
		t.Fatal("nonmatching candidate reached storage")
	}
	files, _ := os.ReadDir(filepath.Dir(out.path))
	if len(files) != 0 {
		t.Fatal("gate wrote files")
	}
}
func TestSaveRetainsFullWriteAfterSyncOrCloseFailure(t *testing.T) {
	for _, op := range []string{"sync", "close"} {
		t.Run(op, func(t *testing.T) {
			out := testOutput(t, filepath.Join(t.TempDir(), "saved"))
			out.root = &faultDir{dirOps: out.root, rules: []faultRule{{op: op, nth: 0, err: errors.New("injected " + op)}}}
			identity := goldenIdentity(t)
			result := out.saveIdentity(&identity, addressMatcher{}, false)
			if len(result.Unverified) != 1 {
				t.Fatalf("complete file lost: %v", result)
			}
			data, err := os.ReadFile(result.Unverified[0])
			if err != nil || len(data) != 64 {
				t.Fatal("no complete recovery data")
			}
			out.root.(*faultDir).rules = nil
			result = out.saveIdentity(&identity, addressMatcher{}, false)
			if len(result.Verified) == 0 {
				t.Fatalf("retry failed: %v", result)
			}
		})
	}
}
func TestSaveReadbackDetectsReplacementAndHardLinkCorruption(t *testing.T) {
	for _, inPlace := range []bool{false, true} {
		t.Run(map[bool]string{false: "entry-replacement", true: "shared-inode-mutation"}[inPlace], func(t *testing.T) {
			dir := t.TempDir()
			out := testOutput(t, filepath.Join(dir, "saved"))
			original := out.root
			out.root = &faultDir{dirOps: original, link: func(a, b string) error {
				if err := original.Link(a, b); err != nil {
					return err
				}
				if !inPlace {
					if err := original.Remove(b); err != nil {
						return err
					}
				}
				return os.WriteFile(filepath.Join(dir, b), make([]byte, 64), 0600)
			}}
			identity := goldenIdentity(t)
			result := out.saveIdentity(&identity, addressMatcher{}, false)
			if len(result.Verified) != 1 || !strings.Contains(strings.Join(result.Deviations, " "), "verification") {
				t.Fatalf("bad recovery outcome: %v", result)
			}
			data, err := os.ReadFile(result.Verified[0])
			if err != nil {
				t.Fatal(err)
			}
			assertHexEqual(t, "recovered", data, goldenX25519Private+goldenEd25519Seed)
		})
	}
}
