package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRecordExportCannotModifyStore(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "NetworkCache", "Version 16", "Records", "partition", "Resource", "record")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, dest := range []string{filepath.Dir(path), filepath.Join(root, "NetworkCache", "exports")} {
		var out, diag bytes.Buffer
		code := run([]string{"parse-record", "-export-bodies", dest, path}, &out, &diag)
		if code != 1 || !strings.Contains(diag.String(), "outside the evidence") {
			t.Fatalf("code=%d diagnostic=%s", code, &diag)
		}
	}
}

func TestRecordEvidenceRoot(t *testing.T) {
	root := t.TempDir()
	for _, test := range []struct {
		name, store, record string
	}{
		{"legacy CacheStorage", "CacheStorage", "CacheStorage/origin/Version 17/Records/record"},
		{"standalone version", "Version 16", "Version 16/Records/record"},
		{"renamed store", "cache-copy", "cache-copy/Records/partition/Resource/record"},
		{"detached record", "loose", "loose/record"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := filepath.Join(root, test.store)
			record := filepath.Join(root, test.record)
			if err := os.MkdirAll(filepath.Dir(record), 0700); err != nil {
				t.Fatal(err)
			}
			if test.name == "renamed store" {
				if err := os.WriteFile(filepath.Join(store, "salt"), make([]byte, 8), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if got := recordEvidenceRoot(record); got != store {
				t.Fatalf("evidence root = %q, want %q", got, store)
			}
		})
	}
}

func TestInvalidArgumentCombinations(t *testing.T) {
	for _, args := range [][]string{
		{"version", "extra"},
		{"scan", "-match", "x", "-export-matches-only", t.TempDir()},
		{"parse-record", "-kind", "typo", "-salt", "missing", "missing"},
	} {
		var out, diag bytes.Buffer
		if code := run(args, &out, &diag); code != 2 {
			t.Fatalf("%v: code=%d diagnostics=%s", args, code, &diag)
		}
	}
}
