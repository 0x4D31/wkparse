package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x4d31/wkparse/pkg/persist"
	"github.com/0x4d31/wkparse/pkg/scanner"
	"github.com/0x4d31/wkparse/pkg/webkit"
	"howett.net/plist"
)

func TestOutputCannotReplaceEvidenceOrExistingReport(t *testing.T) {
	root, dest := t.TempDir(), t.TempDir()
	var out, diag bytes.Buffer
	for _, path := range []string{filepath.Join(root, "source"), filepath.Join(dest, "report")} {
		if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		if run([]string{"scan", "-out", path, root}, &out, &diag) == 0 {
			t.Fatal("accepted existing file")
		}
		if b, err := os.ReadFile(path); err != nil || string(b) != "keep" {
			t.Fatal("output modified existing file")
		}
	}
	newPath := filepath.Join(root, "new-report")
	if run([]string{"scan", "-out", newPath, root}, &out, &diag) == 0 {
		t.Fatal("accepted report inside input")
	}
	if _, err := os.Stat(newPath); !os.IsNotExist(err) {
		t.Fatal("created report inside input")
	}
	if run([]string{"scan", "-out", filepath.Join(dest, "fresh"), root}, &out, &diag) != 0 {
		t.Fatal(diag.String())
	}
}

func TestCLIWorkflows(t *testing.T) {
	// version & help
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "wkparse ") {
		t.Fatalf("version failed: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := run([]string{"-h"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "wkparse scan") {
		t.Fatalf("help failed: code=%d out=%q", code, out.String())
	}
	if code := run([]string{"scan", "-format", "bogus", "."}, &out, &errOut); code != 2 {
		t.Fatalf("invalid format exit code = %d, want 2", code)
	}

	// Build minimal fixture with origin + HSTS + MediaCache
	dir := t.TempDir()
	appDir := filepath.Join(dir, "private", "var", "mobile", "Containers", "Data", "Application", "11111111-2222-3333-4444-555555555555")
	originDir := filepath.Join(appDir, "Library", "WebKit", "WebsiteData", "Default", "aabb")
	mediaDir := filepath.Join(appDir, "tmp", "WebKit", "MediaCache")
	_ = os.MkdirAll(originDir, 0o755)
	_ = os.MkdirAll(mediaDir, 0o755)

	mcm, _ := plist.Marshal(map[string]any{"MCMMetadataIdentifier": "com.apple.mobilesafari"}, plist.BinaryFormat)
	_ = os.WriteFile(filepath.Join(appDir, ".com.apple.mobile_container_manager.metadata.plist"), mcm, 0o644)

	origEnc := persist.NewEncoder()
	origEnc.String("https")
	origEnc.String("top.test")
	origEnc.Bool(false)
	origEnc.String("https")
	origEnc.String("frame.test")
	origEnc.Bool(false)
	originPath := filepath.Join(originDir, "origin")
	_ = os.WriteFile(originPath, origEnc.Bytes(), 0o644)

	mcData, _ := plist.Marshal(map[string]any{
		"lastmodtime":   693506476.0,
		"checkedinlist": map[string]any{"https://media.test/clip.mp4": "/tmp/CachedMedia-1"},
	}, plist.BinaryFormat)
	_ = os.WriteFile(filepath.Join(mediaDir, "diskcacherepository.plist"), mcData, 0o644)

	// parse-origin
	out.Reset()
	errOut.Reset()
	if code := run([]string{"parse-origin", originPath}, &out, &errOut); code != 0 {
		t.Fatalf("parse-origin failed: code=%d err=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"cross_origin": true`) {
		t.Fatalf("parse-origin unexpected output: %s", out.String())
	}

	// scan summary
	out.Reset()
	if code := run([]string{"scan", "-format", "summary", dir}, &out, &errOut); code != 0 {
		t.Fatalf("scan summary failed: code=%d err=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "com.apple.mobilesafari") || !strings.Contains(out.String(), "1 media") {
		t.Fatalf("scan summary missing expected lines:\n%s", out.String())
	}

	// scan json
	out.Reset()
	if code := run([]string{"scan", "-format", "json", dir}, &out, &errOut); code != 0 {
		t.Fatalf("scan json failed: code=%d err=%s", code, errOut.String())
	}
	var rep scanner.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("scan json invalid: %v", err)
	}
	if rep.Summary.Origins != 1 || rep.Summary.CrossOriginStores != 1 || rep.Summary.MediaCacheEntries != 1 {
		t.Fatalf("unexpected report summary: %+v", rep.Summary)
	}

	// scan csv
	out.Reset()
	if code := run([]string{"scan", "-format", "csv", dir}, &out, &errOut); code != 0 {
		t.Fatalf("scan csv failed: code=%d err=%s", code, errOut.String())
	}
	rows, err := csv.NewReader(&out).ReadAll()
	if err != nil || len(rows) != 2 || rows[0][0] != "timestamp_utc" || rows[0][1] != "time_source" || rows[1][3] != "media_cache" {
		t.Fatalf("unexpected csv rows: %+v err=%v", rows, err)
	}

	// -max-decompress-mib overflow must fail cleanly with exit code 2
	out.Reset()
	errOut.Reset()
	if code := run([]string{"scan", "-max-decompress-mib", "9000000000000000000", dir}, &out, &errOut); code != 2 {
		t.Fatalf("overflow -max-decompress-mib exit code = %d, want 2", code)
	}

	// scan graph
	out.Reset()
	if code := run([]string{"scan", "-format", "graph", dir}, &out, &errOut); code != 0 {
		t.Fatalf("scan graph failed: code=%d err=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"cross_origin_client"`) || strings.Contains(out.String(), "0001-01-01") {
		t.Fatalf("unexpected graph jsonl: %s", out.String())
	}
}

func TestBodyDigestLabel(t *testing.T) {
	full := webkit.BodyInfo{DecodedSHA256: "aaaa"}
	if got := bodyDigestLabel(full); got != "sha256=aaaa" {
		t.Fatalf("full digest label = %q, want sha256=aaaa", got)
	}
	trunc := webkit.BodyInfo{DecodeTruncated: true, DecodedPrefixSHA256: "bbbb"}
	if got := bodyDigestLabel(trunc); got != "prefix_sha256=bbbb" {
		t.Fatalf("truncated digest label = %q, want prefix_sha256=bbbb", got)
	}
}
