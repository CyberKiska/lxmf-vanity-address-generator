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

func TestInspectRawAndMaskedCorpusPreservesInput(t *testing.T) {
	data, err := os.ReadFile("testdata/rns-identity-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct{ Raw, Private, Address string }
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, vector := range corpus.Vectors {
		for _, encoded := range []string{vector.Raw, vector.Private} {
			path := filepath.Join(t.TempDir(), "disposable")
			raw := mustDecodeHex(t, encoded)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := parseArgs([]string{"--inspect", path}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			if code := run(context.Background(), cfg, &stdout, io.Discard); code != 0 {
				t.Fatalf("inspect status %d", code)
			}
			if !strings.Contains(stdout.String(), vector.Address) || strings.Contains(stdout.String(), encoded) {
				t.Fatal("inspection mismatch or private disclosure")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, raw) {
				t.Fatal("inspection changed imported bytes")
			}
		}
	}
}
func TestInspectRejectsSizesAndSearchOptions(t *testing.T) {
	for _, size := range []int{0, 63, 65, 100000} {
		path := filepath.Join(t.TempDir(), "disposable")
		os.WriteFile(path, make([]byte, size), 0600)
		var identity Identity
		if _, err := inspectIdentity(path, &identity); err == nil {
			t.Fatalf("accepted size %d", size)
		}
	}
	for _, args := range [][]string{{"--inspect", "file", "--prefix", "a"}, {"--inspect", "file", "--workers", "1"}, {"--inspect", "file", "--include-private-exports"}} {
		if _, err := parseArgs(args, io.Discard); err == nil {
			t.Fatal("inspection allowed explicit search option")
		}
	}
	var identity Identity
	if _, err := inspectIdentity(t.TempDir(), &identity); err == nil {
		t.Fatal("inspection accepted directory")
	}
}
