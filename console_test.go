package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type blockedWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}
func TestConsoleBoundedQueueAndClose(t *testing.T) {
	w := &blockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	c := newConsole(w)
	defer func() { close(w.release); <-c.done }()
	c.status("first\n")
	<-w.entered
	for range 100 {
		c.status("dropped when full\n")
	}
	if len(c.messages) != cap(c.messages) {
		t.Fatal("status queue not bounded")
	}
	start := time.Now()
	c.close(time.Millisecond)
	if time.Since(start) > time.Second {
		t.Fatal("close blocked")
	}
}
func TestRunSavesAndReturnsWithBlockedStderr(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "saved")
	w := &blockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	defer close(w.release)
	raw := goldenRandomInput(t)
	cfg, err := parseArgs([]string{"--prefix", goldenLXMFAddress, "--workers", "1", "--out", path, "--allow-inherited-windows-acl"}, io.Discard)
	// Windows acknowledgement is platform-specific; construct the config directly.
	if err != nil {
		t.Fatal(err)
	}
	cfg.allowInheritedWinACL = false
	if os.PathSeparator == '\\' {
		cfg.allowInheritedWinACL = true
	}
	var stdout bytes.Buffer
	code := runWithDependencies(context.Background(), cfg, &stdout, w, runDependencies{
		rng:            readerFunc(func(p []byte) (int, error) { <-w.entered; return copy(p, raw), nil }),
		consoleTimeout: time.Millisecond,
		signals:        make(chan os.Signal),
	})
	if code != 0 && code != 3 {
		t.Fatalf("save failed: %d: %s", code, stdout.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertHexEqual(t, "saved", data, goldenX25519Private+goldenEd25519Seed)
	if !strings.Contains(stdout.String(), goldenLXMFAddress) {
		t.Fatal("public result absent")
	}
}
func TestResultDeliveryFailurePreservesSavedIdentity(t *testing.T) {
	cfg, err := parseArgs([]string{"--prefix", goldenLXMFAddress, "--workers", "1", "--out", filepath.Join(t.TempDir(), "saved")}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	cfg.allowInheritedWinACL = os.PathSeparator == '\\'
	code := runWithDependencies(context.Background(), cfg, errorWriter{}, io.Discard, runDependencies{rng: &repeatingReader{pattern: goldenRandomInput(t)}, signals: make(chan os.Signal)})
	if code != 3 {
		t.Fatalf("saved result delivery failure: %d", code)
	}
	if _, err := os.Stat(cfg.outPath); err != nil {
		t.Fatal("saved identity lost")
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
