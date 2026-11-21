package scanner

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x4d31/wkparse/pkg/persist"
	_ "modernc.org/sqlite"
)

func mustWrite(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func findAnomaly(r *Report, code string) bool {
	for _, a := range r.Anomalies {
		if a.Code == code {
			return true
		}
	}
	return false
}

func TestCoverageGapsAndParseErrorsAreReported(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "private", "var", "mobile", "Containers", "Data", "Application", "1DF3C4EC-B1DB-4B74-8B62-3A5D12CBB05C")
	itp := filepath.Join(app, "Library", "WebKit", "WebsiteData", "ResourceLoadStatistics")
	// WAL present, main database missing (seen in the iLEAPP public ITP dataset).
	mustWrite(t, filepath.Join(itp, "observations.db-wal"), []byte("7\x7f\x06\x82 wal frames"))
	// Corrupt origin file and an HSTS.plist that is not a plist.
	mustWrite(t, filepath.Join(app, "Library", "WebKit", "WebsiteData", "Default", "aa", "bb", "origin"), []byte{0xff})
	mustWrite(t, filepath.Join(app, "Library", "Caches", "com.example.app", "HSTS.plist"), []byte("not a plist"))

	rep, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	foundWAL := false
	for _, g := range rep.CoverageGaps {
		if strings.Contains(g, "observations.db-wal") && strings.Contains(g, "without observations.db") {
			foundWAL = true
		}
	}
	if !foundWAL {
		t.Fatalf("expected WAL-only coverage gap, got %v", rep.CoverageGaps)
	}
	if !findAnomaly(rep, "artifact_parse_error") {
		t.Fatalf("expected artifact_parse_error anomalies, got %+v", rep.Anomalies)
	}
	n := 0
	for _, a := range rep.Anomalies {
		if a.Code == "artifact_parse_error" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("expected 2 artifact_parse_error (origin, HSTS), got %d: %+v", n, rep.Anomalies)
	}
}

func TestLegacyCacheStorageLayoutIsDiscovered(t *testing.T) {
	root := t.TempDir()
	// <CacheStorage root>/<originKeyHash>/Version 16/Records/<partition>/<uniqueName>/<hash>
	vdir := filepath.Join(root, "Library", "Caches", "com.example.app", "WebKit", "CacheStorage", strings.Repeat("ab", 20), "Version 16")
	mustWrite(t, filepath.Join(vdir, "salt"), []byte("01234567"))
	mustWrite(t, filepath.Join(vdir, "Records", strings.Repeat("1", 40), "4C1A6A3E-0000-4000-8000-000000000001", strings.Repeat("2", 40)), []byte{0})

	rep, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	stores := 0
	for _, c := range rep.Containers {
		stores += len(c.CacheStorages)
	}
	if stores != 1 {
		t.Fatalf("expected the legacy CacheStorage store to be discovered, got containers=%+v", rep.Containers)
	}
	if !findAnomaly(rep, "cachestorage_parse_error") {
		t.Fatalf("garbage record should surface as cachestorage_parse_error: %+v", rep.Anomalies)
	}
}

func TestITPInteractionFlagIsASignalNotAnAnomaly(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "Library", "Containers", "com.example.app", "Data", "Library", "WebKit", "WebsiteData", "ResourceLoadStatistics")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	db, _ := sql.Open("sqlite", filepath.Join(dir, "observations.db"))
	_, _ = db.Exec(`CREATE TABLE ObservedDomains (domainID INTEGER PRIMARY KEY, registrableDomain TEXT, lastSeen REAL, hadUserInteraction INTEGER, mostRecentUserInteractionTime REAL, grandfathered INTEGER, isPrevalent INTEGER, isVeryPrevalent INTEGER, dataRecordsRemoved INTEGER)`)
	_, _ = db.Exec(`CREATE TABLE SubframeUnderTopFrameDomains (subFrameDomainID INTEGER, lastUpdated REAL, topFrameDomainID INTEGER)`)
	_, _ = db.Exec(`INSERT INTO ObservedDomains VALUES (1,'google.com',1760000000,1,1760000000,0,0,0,0),(2,'gstatic.com',1760000005,0,0,0,0,0,0)`)
	_, _ = db.Exec(`INSERT INTO SubframeUnderTopFrameDomains VALUES (2,1760000005,1)`)
	_ = db.Close()

	rep, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Anomalies != 0 || rep.Summary.ContextSignals != 1 || rep.Signals[0].Code != "third_party_without_user_interaction" {
		t.Fatalf("expected one context signal and no anomalies: summary=%+v anomalies=%+v signals=%+v", rep.Summary, rep.Anomalies, rep.Signals)
	}
}

func TestLocalStorageOriginAttribution(t *testing.T) {
	root := t.TempDir()
	odir := filepath.Join(root, "Library", "Containers", "com.example.app", "Data", "Library", "WebKit", "WebsiteData", "Default", "aa", "bb")
	oe := persist.NewEncoder()
	oe.String("https")
	oe.String("top.test")
	oe.Bool(false)
	oe.String("https")
	oe.String("frame.test")
	oe.Bool(false)
	mustWrite(t, filepath.Join(odir, "origin"), oe.Bytes())
	lsPath := filepath.Join(odir, "LocalStorage", "localstorage.sqlite3")
	_ = os.MkdirAll(filepath.Dir(lsPath), 0o755)
	db, _ := sql.Open("sqlite", lsPath)
	_, _ = db.Exec(`CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB NOT NULL ON CONFLICT FAIL)`)
	_, _ = db.Exec(`INSERT INTO ItemTable VALUES ('k', X'7600')`)
	_ = db.Close()

	rep, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, c := range rep.Containers {
		for _, e := range c.LocalStorageEntries {
			got = e.Origin
		}
	}
	if got != "https://frame.test (top=https://top.test)" {
		t.Fatalf("LocalStorage origin = %q", got)
	}
	if o := localStorageOrigin("/x/https_legacy.test_0.localstorage"); o != "https://legacy.test" {
		t.Fatalf("legacy origin = %q", o)
	}
	if o := localStorageOrigin("/x/http_legacy.test_8080.localstorage"); o != "http://legacy.test:8080" {
		t.Fatalf("legacy origin with port = %q", o)
	}
}

func TestBackupPathsUseManifestProvenance(t *testing.T) {
	src := t.TempDir()
	itpPath := filepath.Join(src, "observations.db")
	db, _ := sql.Open("sqlite", itpPath)
	_, _ = db.Exec(`CREATE TABLE ObservedDomains (domainID INTEGER PRIMARY KEY, registrableDomain TEXT, lastSeen REAL, hadUserInteraction INTEGER, mostRecentUserInteractionTime REAL, grandfathered INTEGER, isPrevalent INTEGER, isVeryPrevalent INTEGER, dataRecordsRemoved INTEGER)`)
	_, _ = db.Exec(`INSERT INTO ObservedDomains VALUES (1,'a.test',1760000000,1,0,0,0,0,0)`)
	_ = db.Close()
	raw, _ := os.ReadFile(itpPath)

	bRoot := t.TempDir()
	rel := "Library/WebKit/WebsiteData/ResourceLoadStatistics/observations.db"
	sum := sha1.Sum([]byte("AppDomainGroup-group.com.example-" + rel))
	fid := hex.EncodeToString(sum[:])
	mustWrite(t, filepath.Join(bRoot, fid[:2], fid), raw)
	mdb, _ := sql.Open("sqlite", filepath.Join(bRoot, "Manifest.db"))
	if _, err := mdb.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	_, _ = mdb.Exec(`CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)`)
	_, _ = mdb.Exec(`INSERT INTO Files VALUES (?, 'AppDomainGroup-group.com.example', ?, 1, X'')`, fid, rel)
	// The manifest table and row live in its WAL until this connection closes.
	defer mdb.Close()

	rep, err := Scan(bRoot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Containers) != 1 || len(rep.Containers[0].ITPStores) != 1 {
		t.Fatalf("unexpected containers: %+v", rep.Containers)
	}
	c := rep.Containers[0]
	if c.Owner != "group.com.example (AppGroup)" {
		t.Fatalf("owner = %q", c.Owner)
	}
	want := "backup:AppDomainGroup-group.com.example/" + rel
	if got := c.ITPStores[0].Path; got != want {
		t.Fatalf("ITP path = %q, want %q", got, want)
	}
	if len(rep.BackupFiles) != 1 || rep.BackupFiles[0].FileID != fid || rep.BackupFiles[0].ReportPath != want {
		t.Fatalf("backup provenance mismatch: %+v", rep.BackupFiles)
	}
	if strings.Contains(c.Root, os.TempDir()) && strings.Contains(c.Root, "wkparse-backup-") {
		t.Fatalf("container root still points into staging: %s", c.Root)
	}
}
