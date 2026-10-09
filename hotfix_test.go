package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// An unsupported directory flush is a platform notice, not a deviation, so a
// complete save still exits 0 (previously every Windows save exited 3).
func TestUnsupportedDirectorySyncIsNoticeNotDeviation(t *testing.T) {
	identity := goldenIdentity(t)
	matcher, _ := newAddressMatcher(goldenLXMFAddress[:1], "")
	out := testOutput(t, filepath.Join(t.TempDir(), "saved"))
	if runtime.GOOS != "windows" {
		// Sync #1 is the identity temporary; #2 is the directory flush.
		out.root = &faultDir{dirOps: out.root, rules: []faultRule{{op: "sync", nth: 2, err: syscall.EINVAL}}}
	}
	result := out.saveIdentity(&identity, matcher, false)
	if !result.saved() || len(result.Deviations) != 0 || len(result.Unverified) != 0 {
		t.Fatalf("expected a clean save, got %+v", result)
	}
	if len(result.Notices) != 1 || result.Notices[0] != errDirSyncUnsupported.Error() {
		t.Fatalf("expected only the directory-sync notice, got %q", result.Notices)
	}
}

// A real directory sync failure stays a deviation.
func TestDirectorySyncIOErrorRemainsDeviation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory sync is not attempted on Windows")
	}
	identity := goldenIdentity(t)
	matcher, _ := newAddressMatcher(goldenLXMFAddress[:1], "")
	out := testOutput(t, filepath.Join(t.TempDir(), "saved"))
	out.root = &faultDir{dirOps: out.root, rules: []faultRule{{op: "sync", nth: 2, err: syscall.EIO}}}
	result := out.saveIdentity(&identity, matcher, false)
	if !result.saved() || len(result.Deviations) == 0 || len(result.Notices) != 0 {
		t.Fatalf("I/O failure must be a deviation: %+v", result)
	}
}

// Every file a deviation names as a recovery copy must exist. A sidecar
// collision used to report a temporary that had just been deleted.
func TestSidecarCollisionDoesNotReportDeletedRecoveryFile(t *testing.T) {
	identity := goldenIdentity(t)
	matcher, _ := newAddressMatcher(goldenLXMFAddress[:1], "")
	dir := t.TempDir()
	out := testOutput(t, filepath.Join(dir, "saved"))
	if err := out.preflight(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "saved.txt"), []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := out.saveIdentity(&identity, matcher, false)
	if !result.saved() || result.Verified[0] != filepath.Join(dir, "saved") {
		t.Fatalf("identity must still be saved at the requested name: %+v", result)
	}
	joined := strings.Join(result.Deviations, "\n")
	if strings.Contains(joined, "recovery file") || !strings.Contains(joined, "metadata could not be saved") {
		t.Fatalf("misleading sidecar deviations: %q", result.Deviations)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("unexpected leftover files: %v", entries)
	}
}

// Identity collisions still name the verified recovery file, which exists.
func TestIdentityCollisionNamesExistingRecoveryFile(t *testing.T) {
	identity := goldenIdentity(t)
	matcher, _ := newAddressMatcher(goldenLXMFAddress[:1], "")
	dir := t.TempDir()
	out := testOutput(t, filepath.Join(dir, "saved"))
	if err := out.preflight(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "saved"), []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := out.saveIdentity(&identity, matcher, false)
	if !result.saved() {
		t.Fatalf("recovery copy not saved: %+v", result)
	}
	recovery := result.Verified[0]
	if !strings.Contains(strings.Join(result.Deviations, "\n"), recovery) {
		t.Fatalf("deviations do not name %s: %q", recovery, result.Deviations)
	}
	if data, err := os.ReadFile(recovery); err != nil || len(data) != identityPrivateKeySize {
		t.Fatalf("named recovery file is not the identity: %v", err)
	}
}

// Windows reports unsupported links as ERROR_NOT_SUPPORTED-style errors that
// match errors.ErrUnsupported but never equal syscall.ENOTSUP.
func TestUnsupportedLinkFallsBackToExclusiveCreate(t *testing.T) {
	if !linkUnsupported(fmt.Errorf("link: %w", errors.ErrUnsupported)) {
		t.Fatal("errors.ErrUnsupported not recognised")
	}
	if linkUnsupported(syscall.EPERM) || linkUnsupported(syscall.EACCES) {
		t.Fatal("permission errors must not masquerade as unsupported links")
	}
	identity := goldenIdentity(t)
	matcher, _ := newAddressMatcher(goldenLXMFAddress[:1], "")
	dir := t.TempDir()
	out := testOutput(t, filepath.Join(dir, "saved"))
	out.root = &faultDir{dirOps: out.root, link: func(string, string) error {
		return &os.LinkError{Op: "link", Err: errors.ErrUnsupported}
	}}
	if err := out.preflight(); err != nil || !out.exclusive {
		t.Fatalf("preflight did not select the exclusive fallback: %v", err)
	}
	result := out.saveIdentity(&identity, matcher, false)
	if !result.saved() || result.Verified[0] != filepath.Join(dir, "saved") {
		t.Fatalf("fallback publication failed: %+v", result)
	}
}

func TestWindowsOnlyFlagIsUsageErrorElsewhere(t *testing.T) {
	_, err := parseArgs([]string{"--prefix", "a", "--allow-inherited-windows-acl"}, io.Discard)
	if (runtime.GOOS == "windows") != (err == nil) {
		t.Fatalf("unexpected parse result on %s: %v", runtime.GOOS, err)
	}
}

func TestRecoveryExplainsAnchoredDirectoryLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var buf bytes.Buffer
		c := newConsole(&buf)
		result, _ := recoverWinner(func() saveResult {
			return saveResult{cause: errors.New("no such file or directory"), LocationChanged: true}
		}, make(chan os.Signal), 1500*time.Millisecond, c, func() {})
		c.close(time.Second)
		if result.saved() || !strings.Contains(buf.String(), "never redirected") {
			t.Fatalf("missing anchored-directory explanation: %q", buf.String())
		}
	})
}
