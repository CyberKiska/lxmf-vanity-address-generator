//go:build unix

package main

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestInspectRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	var identity Identity
	if _, err := inspectIdentity(path, &identity); err == nil {
		t.Fatal("inspection accepted FIFO")
	}
}
