package webkit

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/0x4d31/wkparse/pkg/persist"
	"howett.net/plist"
)

func encodeTestKey(e *persist.Encoder, typ, urlStr string) ([20]byte, [20]byte) {
	var h, ph [20]byte
	h[0], h[19] = 0xAA, 0xBB
	ph[0], ph[19] = 0x11, 0x22
	e.String("")
	e.String(typ)
	e.String(urlStr)
	e.String("")
	e.FixedBytes(h[:])
	e.FixedBytes(ph[:])
	return h, ph
}

func makeSelfSignedDER(t testing.TB, cn string, sans []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func buildNetworkCacheFile(t testing.TB, version uint32, salt []byte, urlStr string, body []byte, inline bool, redirectTo string, derCert []byte, gzipBody bool) ([]byte, [20]byte) {
	t.Helper()
	storedBody := body
	if gzipBody {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		_, _ = gw.Write(body)
		_ = gw.Close()
		storedBody = buf.Bytes()
	}

	hdr := persist.NewEncoder()
	hdr.Bool(false) // isNull
	hdr.String(urlStr)
	hdr.String("application/javascript")
	hdr.Int64(int64(len(storedBody)))
	hdr.String("utf-8")
	hdr.String("OK")
	hdr.String("HTTP/2")
	// HTTPHeaderMap
	if gzipBody {
		hdr.Uint64(2)
		hdr.String("Content-Type")
		hdr.String("application/javascript; charset=utf-8")
		hdr.String("Content-Encoding")
		hdr.String("gzip")
	} else {
		hdr.Uint64(1)
		hdr.String("Content-Type")
		hdr.String("application/javascript")
	}
	hdr.Int16(200)
	// optional<CertificateInfo>
	if len(derCert) > 0 {
		hdr.Bool(true)
		if version <= 16 {
			hdr.Enum(2) // LegacyCertificateInfoType::Trust
		}
		hdr.Bool(true) // hasTrust
		plistBytes, err := plist.Marshal(map[string]any{"certs": [][]byte{derCert}}, plist.BinaryFormat)
		if err != nil {
			t.Fatal(err)
		}
		hdr.Uint64(uint64(len(plistBytes)))
		hdr.FixedBytes(plistBytes)
	} else {
		hdr.Bool(false)
	}
	hdr.Enum(1) // Source::Network
	hdr.Enum(0) // Type::Basic
	hdr.Enum(0) // Tainting::Basic
	hdr.Bool(redirectTo != "")
	hdr.Enum(0) // UsedLegacyTLS::No
	hdr.Enum(1) // WasPrivateRelayed::Yes
	hdr.Bool(false)
	if version >= 18 {
		hdr.Enum(0) // IPAddressSpace::Public
	}

	// varyingRequestHeaders
	hdr.Bool(true)
	hdr.Uint64(1)
	hdr.String("Accept-Encoding")
	hdr.String("gzip, br")

	// flags: bit0=isRedirect, bit1=privateRelayed
	flags := uint8(0x02)
	if redirectTo != "" {
		flags |= 0x01
	}
	hdr.Uint8(flags)
	if redirectTo != "" {
		hdr.Bool(true) // std::optional<ResourceRequest> engaged
		hdr.String(redirectTo)
		hdr.Float64(60)
		hdr.String("https://news.example.test/")
		hdr.String("GET")
		hdr.Uint64(1)
		hdr.String("Referer")
		hdr.String("https://news.example.test/")
		hdr.Uint64(0) // encoding fallbacks
		hdr.Enum(0)   // CachePolicy
		hdr.Bool(true)
		hdr.Enum(2) // CrossSite
		hdr.Bool(false)
		hdr.Enum(2) // Medium
		hdr.Enum(3) // Fetch
		hdr.Bool(false)
	}

	// maxAgeCap
	hdr.Bool(true)
	hdr.Float64(86400)
	hdr.EncodeChecksum()
	hdrBytes := hdr.Bytes()

	hdrHash := ComputeSaltedSHA1(salt, hdrBytes)
	bodyHash := ComputeSaltedSHA1(salt, storedBody)

	meta := persist.NewEncoder()
	meta.Uint32(version)
	encodeTestKey(meta, "Resource", urlStr)
	meta.Float64(1760000000.25)
	meta.FixedBytes(hdrHash[:])
	meta.Uint64(uint64(len(hdrBytes)))
	meta.FixedBytes(bodyHash[:])
	meta.Uint64(uint64(len(storedBody)))
	meta.Bool(inline)
	meta.EncodeChecksum()

	var file []byte
	file = append(file, meta.Bytes()...)
	file = append(file, hdrBytes...)
	if inline {
		file = append(file, storedBody...)
	}
	return file, bodyHash
}

func TestNetworkCacheVersions16To18AndOrphanBlobs(t *testing.T) {
	dir := t.TempDir()
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	der := makeSelfSignedDER(t, "cdn.evil.test", []string{"cdn.evil.test"})

	for _, ver := range []uint32{16, 17, 18} {
		verDir := filepath.Join(dir, "Version "+string(rune('0'+ver/10))+string(rune('0'+ver%10)))
		recDir := filepath.Join(verDir, "Records", "1100000000000000000000000000000000000022", "Resource")
		blobsDir := filepath.Join(verDir, "Blobs")
		_ = os.MkdirAll(recDir, 0o755)
		_ = os.MkdirAll(blobsDir, 0o755)
		_ = os.WriteFile(filepath.Join(verDir, "salt"), salt, 0o644)

		payload := []byte("function rce_loader(){ return navigator.gpu; }")
		data, _ := buildNetworkCacheFile(t, ver, salt, "https://cdn.evil.test/rce_loader.js", payload, true, "https://stage2.evil.test/c2_agent.js", der, true)
		recPath := filepath.Join(recDir, strings.Repeat("A", 40))
		_ = os.WriteFile(recPath, data, 0o644)

		// Add a blob in Blobs/ that no record references.
		orphanPayload := []byte("/* deleted exploit stage */ const c2_agent = 'wss://c2.evil.test';")
		orphanSum := ComputeSaltedSHA1(salt, orphanPayload)
		orphanHash := strings.ToUpper(hex.EncodeToString(orphanSum[:]))
		_ = os.WriteFile(filepath.Join(blobsDir, orphanHash), orphanPayload, 0o644)

		exportDir := filepath.Join(dir, "export")
		store, err := ScanNetworkCacheStore(verDir, BodyOptions{
			ExportDir: exportDir,
			Match:     regexp.MustCompile(`rce_loader|c2_agent`),
		})
		if err != nil {
			t.Fatalf("v%d ScanNetworkCacheStore: %v", ver, err)
		}
		if len(store.Records) != 1 {
			t.Fatalf("v%d records = %d, want 1", ver, len(store.Records))
		}
		rec := store.Records[0]
		if !rec.MetaChecksumValid || rec.HeaderHashValid == nil || !*rec.HeaderHashValid || rec.HeaderChecksumValid == nil || !*rec.HeaderChecksumValid || rec.BodyHashValid == nil || !*rec.BodyHashValid {
			t.Fatalf("v%d verification failed: anomalies=%+v", ver, rec.Anomalies)
		}
		if rec.Response == nil || rec.Response.HTTPStatusCode != 200 || len(rec.Response.Certificates) != 1 || rec.Response.Certificates[0].SANs[0] != "cdn.evil.test" {
			t.Fatalf("v%d response/cert mismatch: %+v", ver, rec.Response)
		}
		if ver >= 18 && rec.Response.IPAddressSpace != "Public" {
			t.Fatalf("v18 IPAddressSpace = %q, want Public", rec.Response.IPAddressSpace)
		}
		if !rec.IsRedirect || rec.RedirectRequest == nil || rec.RedirectRequest.URL != "https://stage2.evil.test/c2_agent.js" {
			t.Fatalf("v%d redirect mismatch: %+v", ver, rec.RedirectRequest)
		}
		if rec.Body == nil || !rec.Body.Decompressed || len(rec.Body.Matches) != 1 || rec.Body.Matches[0] != "rce_loader" {
			t.Fatalf("v%d body mismatch: %+v", ver, rec.Body)
		}
		if len(store.OrphanBlobs) != 1 || len(store.OrphanBlobs[0].Body.Matches) != 1 || store.OrphanBlobs[0].Body.Matches[0] != "c2_agent" {
			t.Fatalf("v%d orphan blob mismatch: %+v", ver, store.OrphanBlobs)
		}
	}
}

func TestSubResourcesAndCacheStorageV19AndOrigin(t *testing.T) {
	dir := t.TempDir()
	salt := []byte{9, 8, 7, 6, 5, 4, 3, 2}

	// 1. SubResources record
	subHdr := persist.NewEncoder()
	subHdr.Uint64(1)
	encodeTestKey(subHdr, "Resource", "https://ads.evil.test/frame.js")
	subHdr.Float64(1760000100)
	subHdr.Float64(1760000050)
	subHdr.Bool(false) // non-transient
	subHdr.Bool(false) // isSameSite
	subHdr.Bool(false) // isAppInitiated
	subHdr.String("https://news.example.test/")
	subHdr.Uint64(0)
	subHdr.Enum(2)
	subHdr.EncodeChecksum()
	hdrBytes := subHdr.Bytes()
	hdrHash := ComputeSaltedSHA1(salt, hdrBytes)
	emptyHash := ComputeSaltedSHA1(salt, nil)

	meta := persist.NewEncoder()
	meta.Uint32(17)
	encodeTestKey(meta, "SubResources", "https://news.example.test/")
	meta.Float64(1760000100)
	meta.FixedBytes(hdrHash[:])
	meta.Uint64(uint64(len(hdrBytes)))
	meta.FixedBytes(emptyHash[:])
	meta.Uint64(0)
	meta.Bool(true)
	meta.EncodeChecksum()
	subPath := filepath.Join(dir, strings.Repeat("B", 40))
	_ = os.WriteFile(subPath, append(meta.Bytes(), hdrBytes...), 0o644)

	rec, err := ParseNetworkCacheRecord(subPath, salt, BodyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Subresources) != 1 || rec.Subresources[0].Key.Identifier != "https://ads.evil.test/frame.js" || rec.HeaderChecksumValid == nil || !*rec.HeaderChecksumValid {
		t.Fatalf("SubResources mismatch: %+v", rec)
	}

	// 2. CacheStorage v19 record
	body := []byte(`{"stage":2}`)
	csHdr := persist.NewEncoder()
	csHdr.Float64(1760000200)
	csHdr.Uint64(uint64(len(body)))
	csHdr.Enum(0) // request guard
	// ResourceRequest
	csHdr.String("https://sw.evil.test/payload.json")
	csHdr.Float64(60)
	csHdr.String("https://sw.evil.test/")
	csHdr.String("GET")
	csHdr.Uint64(0)
	csHdr.Uint64(0)
	csHdr.Enum(0)
	csHdr.Bool(true)
	csHdr.Enum(1)
	csHdr.Bool(false)
	csHdr.Enum(1)
	csHdr.Enum(3)
	csHdr.Bool(false)
	// FetchOptions
	csHdr.Enum(15) // script
	csHdr.Enum(3)  // cors
	csHdr.Enum(1)  // same-origin
	csHdr.Enum(0)
	csHdr.Enum(0)
	csHdr.Enum(0)
	csHdr.String("")
	csHdr.Bool(false)
	csHdr.String("https://sw.evil.test/")
	csHdr.Enum(4) // response guard
	csHdr.Bool(false)
	// ResourceResponseData v19
	csHdr.String("https://sw.evil.test/payload.json")
	csHdr.String("application/json")
	csHdr.Int64(int64(len(body)))
	csHdr.String("utf-8")
	csHdr.String("OK")
	csHdr.String("HTTP/2")
	csHdr.Uint64(0)
	csHdr.Int16(200)
	csHdr.Bool(false)
	csHdr.Enum(1)
	csHdr.Enum(0)
	csHdr.Enum(0)
	csHdr.String("")
	csHdr.Enum(0)
	csHdr.Uint32(1 << 4) // RequestIncludesCredentials
	csHdr.Uint64(uint64(len(body)))
	csHdr.EncodeChecksum()
	csHdrBytes := csHdr.Bytes()

	csMeta := persist.NewEncoder()
	csMeta.Uint32(19)
	encodeTestKey(csMeta, "v1-cache", "https://sw.evil.test/payload.json")
	csMeta.Float64(1760000200)
	h1 := ComputeSaltedSHA1(salt, csHdrBytes)
	h2 := ComputeSaltedSHA1(salt, body)
	csMeta.FixedBytes(h1[:])
	csMeta.Uint64(uint64(len(csHdrBytes)))
	csMeta.FixedBytes(h2[:])
	csMeta.Uint64(uint64(len(body)))
	csMeta.Bool(true)
	csMeta.EncodeChecksum()
	csPath := filepath.Join(dir, strings.Repeat("C", 40))
	rawCS := append(append(csMeta.Bytes(), csHdrBytes...), body...)
	_ = os.WriteFile(csPath, rawCS, 0o644)

	csRec, err := ParseCacheStorageRecord(csPath, salt, BodyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if csRec.Response == nil || csRec.Response.URL != "https://sw.evil.test/payload.json" || csRec.HeaderChecksumValid == nil || !*csRec.HeaderChecksumValid || csRec.Body == nil || csRec.Body.Snippet != `{"stage":2}` {
		t.Fatalf("CacheStorage v19 mismatch: %+v", csRec)
	}

	// 3. ClientOrigin file
	origEnc := persist.NewEncoder()
	origEnc.String("https")
	origEnc.String("news.example.test")
	origEnc.Bool(false)
	origEnc.String("https")
	origEnc.String("iframe.evil.test")
	origEnc.Bool(true)
	origEnc.Uint16(8443)
	origPath := filepath.Join(dir, "origin")
	_ = os.WriteFile(origPath, origEnc.Bytes(), 0o644)

	co, err := ParseOriginFile(origPath)
	if err != nil {
		t.Fatal(err)
	}
	if !co.CrossOrigin || co.TopOrigin.String() != "https://news.example.test" || co.ClientOrigin.String() != "https://iframe.evil.test:8443" {
		t.Fatalf("ClientOrigin mismatch: %+v", co)
	}
}

func TestIOS16LegacyProfileSecTrustDERAndBlobFallback(t *testing.T) {
	dir := t.TempDir()
	verDir := filepath.Join(dir, "NetworkCache", "Version 16")
	recDir := filepath.Join(verDir, "Records", strings.Repeat("A", 40), "Resource")
	blobsDir := filepath.Join(verDir, "Blobs")
	_ = os.MkdirAll(recDir, 0o755)
	_ = os.MkdirAll(blobsDir, 0o755)

	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	_ = os.WriteFile(filepath.Join(verDir, "salt"), salt, 0o644)

	// Wrap a real self-signed DER cert inside an ASN.1 DER SET matching Apple SecTrustSerialize.
	certDER := makeSelfSignedDER(t, "cdn.ios16.test", []string{"cdn.ios16.test"})
	secTrustDER, err := asn1.Marshal(struct {
		Key   string `asn1:"utf8"`
		Value []byte
	}{Key: "Cert", Value: certDER})
	if err != nil {
		t.Fatal(err)
	}
	// Wrap in SET (0x31) to mirror real SecTrustSerialize outer tag.
	secTrustSet, err := asn1.MarshalWithParams([]asn1.RawValue{{FullBytes: secTrustDER}}, "set")
	if err != nil {
		t.Fatal(err)
	}

	// Build an iOS 16.0-16.3 v16 Resource header: LegacyCertificateInfoType=2 (Trust) + NO wasPrivateRelayed.
	hdr := persist.NewEncoder()
	hdr.Bool(false) // isNull
	hdr.String("https://cdn.ios16.test/app.js")
	hdr.String("text/javascript")
	hdr.Int64(18)
	hdr.String("utf-8")
	hdr.String("OK")
	hdr.String("HTTP/3.0")
	hdr.Uint64(1)
	hdr.String("Content-Type")
	hdr.String("text/javascript")
	hdr.Int16(200)
	// optional<CertificateInfo> engaged + legacy type=2 (Trust) + hasTrust=true + CFData
	hdr.Bool(true)
	hdr.Enum(2)
	hdr.Bool(true)
	hdr.Uint64(uint64(len(secTrustSet)))
	hdr.FixedBytes(secTrustSet)
	hdr.Enum(2)     // Source = DiskCache
	hdr.Enum(1)     // Type = Default
	hdr.Enum(0)     // Tainting = Basic
	hdr.Bool(false) // isRedirected
	hdr.Enum(0)     // usedLegacyTLS (NO wasPrivateRelayed in iOS 16.0-16.3!)
	hdr.Bool(false) // isRangeRequested
	hdr.Bool(false) // hasVary
	hdr.Uint8(0)    // flags
	hdr.Bool(false) // hasMaxAgeCap
	hdr.EncodeChecksum()
	hdrBytes := hdr.Bytes()

	body := []byte("console.log('ok');")
	hdrHash := ComputeSaltedSHA1(salt, hdrBytes)
	bodyHash := ComputeSaltedSHA1(salt, body)
	bodyHashHex := strings.ToUpper(hex.EncodeToString(bodyHash[:]))

	// Put body ONLY in Blobs/<BodyHash> (no sibling -blob) to test fallback recovery.
	_ = os.WriteFile(filepath.Join(blobsDir, bodyHashHex), body, 0o644)

	meta := persist.NewEncoder()
	meta.Uint32(16)
	encodeTestKey(meta, "Resource", "https://cdn.ios16.test/app.js")
	meta.Float64(1672748068.25)
	meta.FixedBytes(hdrHash[:])
	meta.Uint64(uint64(len(hdrBytes)))
	meta.FixedBytes(bodyHash[:])
	meta.Uint64(uint64(len(body)))
	meta.Bool(false) // external blob
	meta.EncodeChecksum()

	recPath := filepath.Join(recDir, strings.Repeat("F", 40))
	_ = os.WriteFile(recPath, append(meta.Bytes(), hdrBytes...), 0o644)

	autoSalt := FindSaltForRecord(recPath)
	if !bytes.Equal(autoSalt, salt) {
		t.Fatalf("FindSaltForRecord = %x, want %x", autoSalt, salt)
	}

	rec, err := ParseNetworkCacheRecord(recPath, autoSalt, BodyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rec.HeaderChecksumValid == nil || !*rec.HeaderChecksumValid {
		t.Fatalf("expected iOS 16 legacy header checksum valid, anomalies=%+v", rec.Anomalies)
	}
	if rec.BodyHashValid == nil || !*rec.BodyHashValid {
		t.Fatalf("expected Blobs/<BodyHash> fallback body hash valid, anomalies=%+v", rec.Anomalies)
	}
	if rec.Response == nil || len(rec.Response.Certificates) != 1 || !strings.Contains(rec.Response.Certificates[0].Subject, "cdn.ios16.test") {
		t.Fatalf("expected ASN.1 DER SecTrust cert extracted, got %+v", rec.Response)
	}
	if rec.Body == nil || rec.Body.Snippet != "console.log('ok');" {
		t.Fatalf("unexpected fallback body: %+v", rec.Body)
	}
}

func TestPlaintextBodyWithContentEncodingHeaders(t *testing.T) {
	// WebKit/CFNetwork frequently stores bodies already decoded on disk while
	// preserving the original Content-Encoding response header (gzip/br/deflate).
	payload := []byte(`var SERVER_LOG = true; worker.postMessage({ type: 'stage1_rce' });`)
	re := regexp.MustCompile(`stage1_rce`)
	for _, enc := range []string{"gzip", "br", "deflate"} {
		info := AnalyzeBody("inline", payload, enc, "application/javascript", BodyOptions{Match: re})
		if info.Decompressed {
			t.Fatalf("enc=%s: expected already-plaintext body not to be marked Decompressed", enc)
		}
		if info.DecodedSize != int64(len(payload)) || len(info.Matches) != 1 || info.Matches[0] != "stage1_rce" {
			t.Fatalf("enc=%s: plaintext preservation failed: %+v", enc, info)
		}
		if !strings.Contains(info.Snippet, "SERVER_LOG") {
			t.Fatalf("enc=%s: expected JS snippet preserved, got %q", enc, info.Snippet)
		}
	}
}

func TestEnumNameUint64OverflowAndHex40Filter(t *testing.T) {
	if got := enumName(^uint64(0), responseSourceNames); !strings.HasPrefix(got, "unknown(") {
		t.Fatalf("enumName(max uint64) = %q, want unknown(...)", got)
	}
	if isHex40("._04FB6F626888CE4B381268E5BF44C9D6845C3A51") {
		t.Fatal("AppleDouble ._ file must not match isHex40")
	}
	if !isHex40("04FB6F626888CE4B381268E5BF44C9D6845C3A51") {
		t.Fatal("valid 40-hex record name must match isHex40")
	}
}
