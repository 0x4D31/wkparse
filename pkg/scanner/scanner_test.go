package scanner

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/0x4d31/wkparse/pkg/persist"
	"github.com/0x4d31/wkparse/pkg/webkit"
	"howett.net/plist"
	_ "modernc.org/sqlite"
)

func TestEndToEndIOSFFSAndBackup(t *testing.T) {
	ffsRoot := t.TempDir()
	safariContainer := filepath.Join(ffsRoot, "private", "var", "mobile", "Containers", "Data", "Application", "11111111-2222-3333-4444-555555555555")
	_ = os.MkdirAll(safariContainer, 0o755)
	mcm, _ := plist.Marshal(map[string]any{"MCMMetadataIdentifier": "com.apple.mobilesafari"}, plist.BinaryFormat)
	_ = os.WriteFile(filepath.Join(safariContainer, ".com.apple.mobile_container_manager.metadata.plist"), mcm, 0o644)

	// 1. NetworkCache v17 with a redirect + cached JS + orphaned blob
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ncVer := filepath.Join(safariContainer, "Library", "Caches", "WebKit", "NetworkCache", "Version 17")
	recDir := filepath.Join(ncVer, "Records", strings.Repeat("1", 40), "Resource")
	blobsDir := filepath.Join(ncVer, "Blobs")
	_ = os.MkdirAll(recDir, 0o755)
	_ = os.MkdirAll(blobsDir, 0o755)
	_ = os.WriteFile(filepath.Join(ncVer, "salt"), salt, 0o644)

	jsBody := []byte("async function init(){ await navigator.gpu.requestAdapter(); /* rce_loader */ }")
	hdr := persist.NewEncoder()
	hdr.Bool(false)
	hdr.String("https://cdn.evil.test/rce_loader.js")
	hdr.String("application/javascript")
	hdr.Int64(int64(len(jsBody)))
	hdr.String("utf-8")
	hdr.String("OK")
	hdr.String("HTTP/2")
	hdr.Uint64(1)
	hdr.String("Content-Type")
	hdr.String("application/javascript")
	hdr.Int16(200)
	hdr.Bool(false) // no cert
	hdr.Enum(1)
	hdr.Enum(0)
	hdr.Enum(0)
	hdr.Bool(false)
	hdr.Enum(0)
	hdr.Enum(0)
	hdr.Bool(false)
	hdr.Bool(false) // no vary
	hdr.Uint8(0)    // no redirect/relay
	hdr.Bool(false) // no maxAgeCap
	hdr.EncodeChecksum()
	hdrBytes := hdr.Bytes()
	hHash := webkit.ComputeSaltedSHA1(salt, hdrBytes)
	bHash := webkit.ComputeSaltedSHA1(salt, jsBody)

	meta := persist.NewEncoder()
	meta.Uint32(17)
	meta.String("")
	meta.String("Resource")
	meta.String("https://cdn.evil.test/rce_loader.js")
	meta.String("")
	var kh, ph [20]byte
	kh[0], ph[0] = 0xAA, 0x11
	meta.FixedBytes(kh[:])
	meta.FixedBytes(ph[:])
	meta.Float64(1760000010)
	meta.FixedBytes(hHash[:])
	meta.Uint64(uint64(len(hdrBytes)))
	meta.FixedBytes(bHash[:])
	meta.Uint64(uint64(len(jsBody)))
	meta.Bool(true)
	meta.EncodeChecksum()
	recData := append(append(meta.Bytes(), hdrBytes...), jsBody...)
	_ = os.WriteFile(filepath.Join(recDir, strings.Repeat("A", 40)), recData, 0o644)

	// Orphaned blob simulating deleted stage2 payload
	orphan := []byte("const c2_agent = 'https://c2.evil.test/beacon';")
	ohSum := webkit.ComputeSaltedSHA1(salt, orphan)
	oh := strings.ToUpper(hex.EncodeToString(ohSum[:]))
	_ = os.WriteFile(filepath.Join(blobsDir, oh), orphan, 0o644)

	// 2. WebsiteData/Default cross-origin sidecar
	origDir := filepath.Join(safariContainer, "Library", "WebKit", "WebsiteData", "Default", "tophash", "clienthash")
	_ = os.MkdirAll(origDir, 0o755)
	oe := persist.NewEncoder()
	oe.String("https")
	oe.String("news.example.test")
	oe.Bool(false)
	oe.String("https")
	oe.String("evil.test")
	oe.Bool(false)
	_ = os.WriteFile(filepath.Join(origDir, "origin"), oe.Bytes(), 0o644)

	// 3. ResourceLoadStatistics/observations.db
	itpDir := filepath.Join(safariContainer, "Library", "WebKit", "WebsiteData", "ResourceLoadStatistics")
	_ = os.MkdirAll(itpDir, 0o755)
	itpPath := filepath.Join(itpDir, "observations.db")
	itpDB, _ := sql.Open("sqlite", itpPath)
	_, _ = itpDB.Exec(`CREATE TABLE ObservedDomains (domainID INTEGER PRIMARY KEY, registrableDomain TEXT, lastSeen REAL, hadUserInteraction INTEGER, mostRecentUserInteractionTime REAL, grandfathered INTEGER, isPrevalent INTEGER, isVeryPrevalent INTEGER, dataRecordsRemoved INTEGER);`)
	_, _ = itpDB.Exec(`CREATE TABLE SubframeUnderTopFrameDomains (subFrameDomainID INTEGER, lastUpdated REAL, topFrameDomainID INTEGER);`)
	_, _ = itpDB.Exec(`INSERT INTO ObservedDomains VALUES (1,'news.example.test',1760000000,1,1760000000,0,0,0,0),(2,'evil.test',1760000005,0,0,0,1,0,0);`)
	_, _ = itpDB.Exec(`INSERT INTO SubframeUnderTopFrameDomains VALUES (2,1760000005,1);`)
	_ = itpDB.Close()

	exportDir := filepath.Join(t.TempDir(), "bodies")
	rep, err := Scan(ffsRoot, Options{
		ExportBodiesDir: exportDir,
		Match:           regexp.MustCompile(`rce_loader|c2_agent`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.AcquisitionType != "ios_ffs" {
		t.Fatalf("AcquisitionType = %q, want ios_ffs", rep.AcquisitionType)
	}
	if rep.Summary.Containers != 1 || rep.Containers[0].Owner != "com.apple.mobilesafari" {
		t.Fatalf("unexpected container attribution: %+v", rep.Containers)
	}
	if rep.Summary.NetworkCacheRecords != 1 || rep.Summary.OrphanBlobs != 1 || rep.Summary.CrossOriginStores != 1 || rep.Summary.ITPRelationships != 1 || rep.Summary.BodyMatches != 2 {
		t.Fatalf("unexpected summary: %+v", rep.Summary)
	}
	if len(rep.Graph) < 2 || len(rep.Timeline) < 3 {
		t.Fatalf("expected correlated graph & timeline, got graph=%d timeline=%d", len(rep.Graph), len(rep.Timeline))
	}

	// 4. Verify iOS Backup (Manifest.db) scanning & explicit coverage gap reporting
	bRoot := t.TempDir()
	fidSum := sha1.Sum([]byte("AppDomain-com.apple.mobilesafari-Library/WebKit/WebsiteData/ResourceLoadStatistics/observations.db"))
	fid := hex.EncodeToString(fidSum[:])
	_ = os.MkdirAll(filepath.Join(bRoot, fid[:2]), 0o755)
	itpRaw, _ := os.ReadFile(itpPath)
	_ = os.WriteFile(filepath.Join(bRoot, fid[:2], fid), itpRaw, 0o644)

	mdb, _ := sql.Open("sqlite", filepath.Join(bRoot, "Manifest.db"))
	_, _ = mdb.Exec(`CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB);`)
	_, _ = mdb.Exec(`INSERT INTO Files VALUES (?, 'AppDomain-com.apple.mobilesafari', 'Library/WebKit/WebsiteData/ResourceLoadStatistics/observations.db', 1, X'')`, fid)
	// Hostile path traversal entry in Manifest.db must be ignored cleanly.
	_, _ = mdb.Exec(`INSERT INTO Files VALUES (?, '../../evil', '../../../Library/WebKit/WebsiteData/ResourceLoadStatistics/observations.db', 1, X'')`, fid)
	_ = mdb.Close()

	bRep, err := Scan(bRoot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if bRep.AcquisitionType != "ios_backup" || len(bRep.CoverageGaps) == 0 || bRep.Summary.ObservedDomains != 2 {
		t.Fatalf("unexpected backup report: type=%q gaps=%v summary=%+v", bRep.AcquisitionType, bRep.CoverageGaps, bRep.Summary)
	}

	// Verify standalone copied Version 17 folder scans directly even without a NetworkCache/ parent.
	standaloneDir := filepath.Join(t.TempDir(), "copied_cache")
	sRecDir := filepath.Join(standaloneDir, "Records", strings.Repeat("1", 40), "Resource")
	_ = os.MkdirAll(sRecDir, 0o755)
	_ = os.WriteFile(filepath.Join(standaloneDir, "salt"), salt, 0o644)
	_ = os.WriteFile(filepath.Join(sRecDir, strings.Repeat("2", 40)), recData, 0o644)
	// Also drop a macOS AppleDouble file that must be ignored cleanly.
	_ = os.WriteFile(filepath.Join(sRecDir, "._"+strings.Repeat("2", 40)), []byte("appledouble"), 0o644)
	sRep, err := Scan(standaloneDir, Options{})
	if err != nil {
		t.Fatalf("standalone scan failed: %v", err)
	}
	if sRep.Summary.NetworkCacheRecords != 1 || sRep.Summary.Anomalies != 0 {
		t.Fatalf("unexpected standalone scan summary: %+v anomalies=%+v", sRep.Summary, sRep.Anomalies)
	}

	// Verify zero-timestamp record still counts BodyMatches in Summary.
	zeroRep := &Report{
		Containers: []ContainerReport{
			{
				Owner: "com.apple.mobilesafari",
				NetworkCaches: []webkit.NetworkCacheStore{
					{
						Records: []webkit.NetworkCacheRecord{
							{
								Key: webkit.Key{Identifier: "https://zero.test/payload.js"},
								Body: &webkit.BodyInfo{
									Matches: []string{"rce_loader"},
								},
							},
						},
					},
				},
			},
		},
	}
	finalizeReport(zeroRep)
	if zeroRep.Summary.BodyMatches != 1 {
		t.Fatalf("expected BodyMatches=1 for zero-timestamp record, got %d", zeroRep.Summary.BodyMatches)
	}
}
