//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixDirectoryOwnershipAndModes(t *testing.T) {
	for _, test := range []struct {
		uid        uint32
		mode       os.FileMode
		fail, warn bool
	}{
		{1000, 0700, false, false}, {0, 0700, false, false}, {1001, 0700, true, false},
		{1000, 0770, true, false}, {1000, 0777, true, false}, {0, 0777 | os.ModeSticky, false, true},
	} {
		notice, err := unixDirectoryPolicy(test.uid, test.mode, 1000)
		if (err != nil) != test.fail || (notice != "") != test.warn {
			t.Fatalf("directory policy: %d %o %v", test.uid, test.mode, err)
		}
	}
	dir := t.TempDir()
	os.Chmod(dir, 0770)
	out := testOutput(t, filepath.Join(dir, "saved"))
	if err := out.preflight(); err == nil {
		t.Fatal("group-writable directory accepted")
	}
	out.allowWeak = true
	if err := out.preflight(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(out.notices, " "), "explicitly accepted") {
		t.Fatal("override not explained")
	}
}
func TestProtectionIsRecheckedBeforeSecretWrite(t *testing.T) {
	out := testOutput(t, filepath.Join(t.TempDir(), "saved"))
	if err := out.preflight(); err != nil {
		t.Fatal(err)
	}
	out.root = &faultDir{dirOps: out.root, rules: []faultRule{{op: "chmod", nth: 1, err: os.ErrPermission}}}
	identity := goldenIdentity(t)
	result := out.saveIdentity(&identity, addressMatcher{}, false)
	if result.saved() {
		t.Fatal("save ignored protection failure")
	}
	if fault := out.root.(*faultDir); fault.calls["write"] != 0 {
		t.Fatal("secret written before protection passed")
	}
}
