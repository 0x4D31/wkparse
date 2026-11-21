package stores

import (
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"

	"howett.net/plist"
	_ "modernc.org/sqlite"
)

func TestITPAndWALReadOnly(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observations.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`PRAGMA journal_mode=WAL;`,
		`CREATE TABLE ObservedDomains (
			domainID INTEGER PRIMARY KEY, registrableDomain TEXT NOT NULL UNIQUE,
			lastSeen REAL, hadUserInteraction INTEGER,
			mostRecentUserInteractionTime REAL, grandfathered INTEGER,
			isPrevalent INTEGER, isVeryPrevalent INTEGER, dataRecordsRemoved INTEGER
		);`,
		`CREATE TABLE SubframeUnderTopFrameDomains (subFrameDomainID INTEGER, lastUpdated REAL, topFrameDomainID INTEGER);`,
		`CREATE TABLE TopFrameLoadedThirdPartyScripts (topFrameDomainID INTEGER, subresourceDomainID INTEGER);`,
		`CREATE TABLE OperatingDates (year INTEGER, month INTEGER, monthDay INTEGER);`,
		`INSERT INTO ObservedDomains VALUES (1, 'news.example.test', 1760000000, 1, 1760000000, 0, 0, 0, 0);`,
		`INSERT INTO ObservedDomains VALUES (2, 'evil.test', 1760000005, 0, NULL, NULL, 1, 0, NULL);`,
		`INSERT INTO SubframeUnderTopFrameDomains VALUES (2, NULL, 1);`,
		`INSERT INTO TopFrameLoadedThirdPartyScripts VALUES (1, 2);`,
		`INSERT INTO OperatingDates VALUES (2025, 10, 9);`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %s: %v", s, err)
		}
	}
	// Keep connection open so WAL remains uncheckpointed, verifying forensic copy reads WAL!
	defer db.Close()

	itp, err := ParseITPDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(itp.Domains) != 2 {
		t.Fatalf("domains = %d, want 2", len(itp.Domains))
	}
	if len(itp.Relationships) != 2 {
		t.Fatalf("relationships = %d, want 2: %+v", len(itp.Relationships), itp.Relationships)
	}
	if len(itp.OperatingDates) != 1 || itp.OperatingDates[0] != "2025-10-09" {
		t.Fatalf("operating dates = %+v", itp.OperatingDates)
	}
}

func TestLocalStorageServiceWorkerHSTSAndContainerPlist(t *testing.T) {
	dir := t.TempDir()

	// LocalStorage with UTF-16LE value
	lsPath := filepath.Join(dir, "localstorage.sqlite3")
	lsDB, _ := sql.Open("sqlite", lsPath)
	_, _ = lsDB.Exec(`CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB NOT NULL);`)
	u16 := utf16.Encode([]rune("stage=gpu_escape"))
	blob := make([]byte, len(u16)*2)
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(blob[i*2:], c)
	}
	_, _ = lsDB.Exec(`INSERT INTO ItemTable VALUES ('implant_state', ?)`, blob)
	_ = lsDB.Close()

	entries, err := ParseLocalStorage(lsPath)
	if err != nil || len(entries) != 1 || entries[0].Value != "stage=gpu_escape" {
		t.Fatalf("LocalStorage mismatch: %+v, err=%v", entries, err)
	}

	// ServiceWorkerRegistrations
	swPath := filepath.Join(dir, "ServiceWorkerRegistrations-8.sqlite3")
	swDB, _ := sql.Open("sqlite", swPath)
	_, _ = swDB.Exec(`CREATE TABLE Records (
		key TEXT, origin TEXT, scopeURL TEXT, topOrigin TEXT,
		lastUpdateCheckTime DOUBLE, updateViaCache TEXT, scriptURL TEXT,
		workerType TEXT, referrerPolicy TEXT
	);`)
	_, _ = swDB.Exec(`INSERT INTO Records VALUES ('k1','https://evil.test','https://evil.test/','https://news.example.test',1760000010,'imports','https://evil.test/sw.js','classic','')`)
	_, _ = swDB.Exec(`INSERT INTO Records VALUES ('k2','https://null.test','https://null.test/',NULL,NULL,NULL,'https://null.test/sw.js',NULL,NULL)`)
	_ = swDB.Close()

	sws, err := ParseServiceWorkers(swPath)
	if err != nil || len(sws) != 2 || sws[0].ScriptURL != "https://evil.test/sw.js" || sws[1].LastUpdateCheckTime != nil {
		t.Fatalf("ServiceWorkers mismatch: %+v, err=%v", sws, err)
	}

	// HSTS.plist
	hstsPath := filepath.Join(dir, "HSTS.plist")
	hstsData, _ := plist.Marshal(map[string]any{
		"com.apple.CFNetwork.defaultStorageSession": map[string]any{
			"evil.test": map[string]any{
				"Expiry":             time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
				"Include Subdomains": true,
			},
		},
	}, plist.BinaryFormat)
	_ = os.WriteFile(hstsPath, hstsData, 0o644)
	hsts, err := ParseHSTS(hstsPath)
	if err != nil || len(hsts) != 1 || hsts[0].Host != "evil.test" || !hsts[0].IncludeSubdomains {
		t.Fatalf("HSTS mismatch: %+v, err=%v", hsts, err)
	}

	// MCM container attribution
	mcmData, _ := plist.Marshal(map[string]any{"MCMMetadataIdentifier": "com.apple.mobilesafari"}, plist.BinaryFormat)
	_ = os.WriteFile(filepath.Join(dir, ".com.apple.mobile_container_manager.metadata.plist"), mcmData, 0o644)
	if got := ResolveContainerBundleID(dir); got != "com.apple.mobilesafari" {
		t.Fatalf("ResolveContainerBundleID = %q, want com.apple.mobilesafari", got)
	}

	// MediaCache diskcacherepository.plist
	mcPath := filepath.Join(dir, "diskcacherepository.plist")
	mcData, _ := plist.Marshal(map[string]any{
		"lastmodtime": 693506476.5,
		"checkedinlist": map[string]any{
			"https://media.example.test/video.mp4": "/var/mobile/tmp/CachedMedia-1",
		},
		"checkedoutlist": map[string]any{
			"07328658-5A55-4B06-8D14-EAAD0D0D222F=https://media.example.test/audio.mp3": "/var/mobile/tmp/CachedMedia-2",
		},
	}, plist.BinaryFormat)
	_ = os.WriteFile(mcPath, mcData, 0o644)
	mcs, err := ParseMediaCache(mcPath)
	if err != nil || len(mcs) != 2 || mcs[0].URL != "https://media.example.test/audio.mp3" || mcs[0].State != "checked_out" || mcs[0].LastModified == nil {
		t.Fatalf("MediaCache mismatch: %+v, err=%v", mcs, err)
	}

	// Legacy ServiceWorker schema missing topOrigin/referrerPolicy + HSTS far-future (>292yr) expiry
	swLegacy := filepath.Join(dir, "ServiceWorkerRegistrations-legacy.sqlite3")
	db3, err := sql.Open("sqlite", swLegacy)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db3.Exec(`CREATE TABLE Records(key TEXT, origin TEXT, scopeURL TEXT, lastUpdateCheckTime REAL, scriptURL TEXT);
		INSERT INTO Records VALUES('k1','https://old.test','https://old.test/',1700000000,'https://old.test/sw.js');`)
	_ = db3.Close()
	legacySWs, err := ParseServiceWorkers(swLegacy)
	if err != nil || len(legacySWs) != 1 || legacySWs[0].ScriptURL != "https://old.test/sw.js" {
		t.Fatalf("legacy ServiceWorkers mismatch: %+v, err=%v", legacySWs, err)
	}

	if got := appleTimeFromSeconds(1.5e10); got == nil || got.Year() < 2400 {
		t.Fatalf("expected >292yr CFAbsoluteTime without int64 duration overflow, got %v", got)
	}

	// Overlapping HSTS sessions must both survive in deterministic order.
	hstsMulti := filepath.Join(dir, "HSTS-multi.plist")
	multiData, _ := plist.Marshal(map[string]any{
		"com.apple.CFNetwork.defaultStorageSession": map[string]any{
			"dup.example.test": map[string]any{"Expiry": 700000000.0, "Include Subdomains": true},
		},
		"com.apple.WebKit.secondarySession": map[string]any{
			"dup.example.test": map[string]any{"Expiry": 800000000.0, "Include Subdomains": false},
		},
	}, plist.BinaryFormat)
	_ = os.WriteFile(hstsMulti, multiData, 0o644)
	for i := 0; i < 20; i++ {
		entries, err := ParseHSTS(hstsMulti)
		if err != nil || len(entries) != 2 || !entries[0].IncludeSubdomains || entries[1].IncludeSubdomains {
			t.Fatalf("ParseHSTS non-deterministic on run %d: %+v err=%v", i, entries, err)
		}
	}
}
