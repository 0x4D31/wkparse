package webkit

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/0x4d31/wkparse/pkg/persist"
)

func TestExportConflictAndDuplicate(t *testing.T) {
	opts := BodyOptions{ExportDir: t.TempDir()}
	body := []byte("sample")
	export := func() BodyInfo { return AnalyzeBody("inline", body, "", "text/plain", opts) }
	a, b := export(), export()
	if a.ExportPath == "" || b.ExportPath != a.ExportPath || b.ExportError != "" {
		t.Fatalf("duplicate export: %+v %+v", a, b)
	}
	if err := os.WriteFile(a.ExportPath, []byte("forged"), 0600); err != nil {
		t.Fatal(err)
	}
	c := export()
	if c.ExportPath != "" || c.ExportError == "" {
		t.Fatal("accepted conflicting digest")
	}
	if data, _ := os.ReadFile(a.ExportPath); string(data) != "forged" {
		t.Fatal("overwrote existing export")
	}
	if err := os.Remove(a.ExportPath); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "absent")
	if err := os.Symlink(dest, a.ExportPath); err != nil {
		t.Skip("symlinks unavailable")
	}
	if c = export(); c.ExportPath != "" || c.ExportError == "" {
		t.Fatal("accepted symlink")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("followed symlink")
	}
}

func TestNetworkCacheRejectsUnrelatedParentSalt(t *testing.T) {
	root := filepath.Join(t.TempDir(), "NetworkCache")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "salt"), []byte("12345678"), 0600); err != nil {
		t.Fatal(err)
	}
	if b := FindSaltForRecord(filepath.Join(root, "Version 16", "Records", "rec")); b != nil {
		t.Fatal("unexpected cross-store salt")
	}
}

// buildMetaOnly encodes RecordMetaData with caller-controlled sizes and a valid checksum.
func buildMetaOnly(keyType string, headerSize func(metaLen int) uint64, bodySize uint64, inline bool) []byte {
	var z [20]byte
	enc := func(hs uint64) []byte {
		e := persist.NewEncoder()
		e.Uint32(16)
		encodeTestKey(e, keyType, "https://x.test/")
		e.Float64(1.7e9)
		e.FixedBytes(z[:])
		e.Uint64(hs)
		e.FixedBytes(z[:])
		e.Uint64(bodySize)
		e.Bool(inline)
		e.EncodeChecksum()
		return e.Bytes()
	}
	// Metadata length does not depend on the headerSize value (fixed-width uint64).
	metaLen := len(enc(0))
	return enc(headerSize(metaLen))
}

func TestHeaderSizeOverflowIsAnAnomalyNotAPanic(t *testing.T) {
	// offset + headerSize wraps to 1 (mod 2^64); this used to panic with slice bounds [167:1].
	raw := buildMetaOnly("Resource", func(off int) uint64 { return ^uint64(0) - uint64(off) + 2 }, 0, true)
	for _, parse := range []func() ([]Anomaly, error){
		func() ([]Anomaly, error) {
			r, err := ParseNetworkCacheRecordBytes("rec", raw, nil, BodyOptions{})
			if r == nil {
				return nil, err
			}
			return r.Anomalies, err
		},
		func() ([]Anomaly, error) {
			r, err := ParseCacheStorageRecordBytes("rec", raw, nil, BodyOptions{})
			if r == nil {
				return nil, err
			}
			return r.Anomalies, err
		},
	} {
		anoms, err := parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !hasCode(anoms, "truncated_header") {
			t.Fatalf("expected truncated_header, got %+v", anoms)
		}
	}
}

func TestInlineBodySizeOverflowIsAnAnomaly(t *testing.T) {
	raw := buildMetaOnly("Resource", func(int) uint64 { return 0 }, ^uint64(0), true)
	rec, err := ParseNetworkCacheRecordBytes("rec", raw, nil, BodyOptions{})
	if err != nil || !hasCode(rec.Anomalies, "truncated_body") {
		t.Fatalf("expected truncated_body, err=%v rec=%+v", err, rec)
	}
	cs, err := ParseCacheStorageRecordBytes("rec", raw, nil, BodyOptions{})
	if err != nil || !hasCode(cs.Anomalies, "truncated_body") {
		t.Fatalf("expected CacheStorage truncated_body, err=%v rec=%+v", err, cs)
	}
}

func TestTrailingDataAfterInlineBody(t *testing.T) {
	salt := []byte("01234567")
	data, _ := buildNetworkCacheFile(t, 16, salt, "https://a.test/x.js", []byte("var a=1;"), true, "", nil, false)
	rec, err := ParseNetworkCacheRecordBytes("rec", append(data, 0xde, 0xad), salt, BodyOptions{})
	if err != nil || !hasCode(rec.Anomalies, "trailing_data") {
		t.Fatalf("expected trailing_data, err=%v anomalies=%+v", err, rec.Anomalies)
	}
	clean, err := ParseNetworkCacheRecordBytes("rec", data, salt, BodyOptions{})
	if err != nil || hasCode(clean.Anomalies, "trailing_data") {
		t.Fatalf("unexpected trailing_data on clean record: %+v", clean.Anomalies)
	}
}

func TestDecompressionCapIsFlagged(t *testing.T) {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write(bytes.Repeat([]byte("A"), 1<<20))
	_ = w.Close()

	bi := AnalyzeBody("inline", b.Bytes(), "gzip", "text/plain", BodyOptions{MaxDecompress: 1024})
	if !bi.Decompressed || !bi.DecodeTruncated || bi.DecodedSize != 1024 {
		t.Fatalf("expected truncated 1024-byte decode, got %+v", bi)
	}
	if bi.DecodedSHA256 != "" || bi.DecodedPrefixSHA256 == "" {
		t.Fatalf("truncated decode must not report a full-payload hash: %+v", bi)
	}
	if truncatedBodyAnomaly(&bi, "p") == nil {
		t.Fatal("expected decompression_cap_reached anomaly")
	}

	full := AnalyzeBody("inline", b.Bytes(), "gzip", "text/plain", BodyOptions{MaxDecompress: 2 << 20})
	if full.DecodeTruncated || full.DecodedSize != 1<<20 || full.DecodedSHA256 == "" {
		t.Fatalf("expected full decode, got %+v", full)
	}
}

func TestExportNamingPermissionsAndMatchesOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	re := regexp.MustCompile(`needle`)

	hit := AnalyzeBody("inline", []byte("<html>needle</html>"), "", "text/html", BodyOptions{ExportDir: dir, Match: re, ExportMatchesOnly: true})
	miss := AnalyzeBody("inline", []byte("<html>hay</html>"), "", "text/html", BodyOptions{ExportDir: dir, Match: re, ExportMatchesOnly: true})
	if hit.ExportPath == "" || miss.ExportPath != "" {
		t.Fatalf("matches-only export wrong: hit=%q miss=%q", hit.ExportPath, miss.ExportPath)
	}
	if !strings.HasSuffix(hit.ExportPath, ".html.bin") {
		t.Fatalf("export should use a non-executable .bin suffix: %s", hit.ExportPath)
	}
	fi, err := os.Stat(hit.ExportPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("export should be owner-only, got %v", perm)
	}

	all := AnalyzeBody("inline", []byte("<html>hay</html>"), "", "text/html", BodyOptions{ExportDir: dir, Match: re})
	if all.ExportPath == "" {
		t.Fatal("without ExportMatchesOnly every body is exported")
	}

	// Unknown MIME must not double the .bin suffix.
	raw := AnalyzeBody("inline", []byte{0x00, 0x01, 0x02, 0x03}, "", "application/octet-stream", BodyOptions{ExportDir: dir})
	if raw.ExportPath == "" || strings.HasSuffix(raw.ExportPath, ".bin.bin") || !strings.HasSuffix(raw.ExportPath, ".bin") {
		t.Fatalf("unexpected unknown-MIME export path: %q", raw.ExportPath)
	}

	// Group-writable (umask 0002 default on Linux) should be accepted; world-writable must be rejected.
	gwDir := filepath.Join(t.TempDir(), "gw")
	if err := os.Mkdir(gwDir, 0o775); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(gwDir, 0o775)
	if res := AnalyzeBody("inline", []byte("ok"), "", "text/plain", BodyOptions{ExportDir: gwDir}); res.ExportPath == "" || res.ExportError != "" {
		t.Fatalf("expected 0775 export dir to succeed, got %+v", res)
	}
	wwDir := filepath.Join(t.TempDir(), "ww")
	if err := os.Mkdir(wwDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wwDir, 0o777); err == nil {
		if res := AnalyzeBody("inline", []byte("no"), "", "text/plain", BodyOptions{ExportDir: wwDir}); res.ExportPath != "" || res.ExportError == "" {
			t.Fatalf("expected 0777 export dir to be rejected, got %+v", res)
		}
	}
}

func TestCachesListResolvesCacheNames(t *testing.T) {
	e := persist.NewEncoder()
	e.Uint64(2)
	e.String("v1-static")
	e.String("4C1A6A3E-0000-4000-8000-000000000001")
	e.String("runtime")
	e.String("4C1A6A3E-0000-4000-8000-000000000002")
	p := filepath.Join(t.TempDir(), "cacheslist")
	if err := os.WriteFile(p, e.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	names, err := ReadCachesList(p)
	if err != nil || names["4C1A6A3E-0000-4000-8000-000000000001"] != "v1-static" || names["4C1A6A3E-0000-4000-8000-000000000002"] != "runtime" {
		t.Fatalf("cacheslist mismatch: %v err=%v", names, err)
	}
	if n, err := ReadCachesList(filepath.Join(t.TempDir(), "absent")); n != nil || err != nil {
		t.Fatalf("missing cacheslist should be (nil, nil), got %v %v", n, err)
	}
	if _, err := ReadCachesList(writeTemp(t, []byte{1, 2, 3})); err == nil {
		t.Fatal("expected error on corrupt cacheslist")
	}
}

func TestRecoverAsErrorWrapsPanics(t *testing.T) {
	f := func() (err error) {
		defer recoverAsError(&err, "/x/rec")
		var s []byte
		_ = s[5]
		return nil
	}
	if err := f(); err == nil || !strings.Contains(err.Error(), ErrParserPanic.Error()) {
		t.Fatalf("expected ErrParserPanic, got %v", err)
	}
}

func TestCacheStorageParentSaltDiscovery(t *testing.T) {
	csDir := filepath.Join(t.TempDir(), "CacheStorage")
	verDir := filepath.Join(csDir, "Version 19")
	recDir := filepath.Join(verDir, "Records", strings.Repeat("1", 40), "cache-uuid")
	if err := os.MkdirAll(recDir, 0o755); err != nil {
		t.Fatal(err)
	}
	salt := []byte("87654321")
	if err := os.WriteFile(filepath.Join(csDir, "salt"), salt, 0o600); err != nil {
		t.Fatal(err)
	}
	recPath := filepath.Join(recDir, strings.Repeat("2", 40))
	if err := os.WriteFile(recPath, []byte{0}, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := FindSaltForRecord(recPath); string(got) != string(salt) {
		t.Fatalf("FindSaltForRecord = %q, want %q", got, salt)
	}
	st, err := ScanCacheStorageStore(verDir, BodyOptions{})
	if err != nil || !st.SaltPresent {
		t.Fatalf("expected SaltPresent=true from parent CacheStorage/salt, got st=%+v err=%v", st, err)
	}
}

func hasCode(anoms []Anomaly, code string) bool {
	for _, a := range anoms {
		if a.Code == code {
			return true
		}
	}
	return false
}

func writeTemp(t testing.TB, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
