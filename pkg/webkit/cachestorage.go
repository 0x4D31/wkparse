package webkit

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0x4d31/wkparse/internal/evidence"
	"github.com/0x4d31/wkparse/pkg/persist"
)

// ParseCacheStorageRecord decodes a WebKit DOM/ServiceWorker CacheStorage record (versions 16-19).
func ParseCacheStorageRecord(path string, salt []byte, opts BodyOptions) (*CacheStorageRecord, error) {
	raw, err := evidence.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCacheStorageRecordBytes(path, raw, salt, opts)
}

// ParseCacheStorageRecordBytes decodes CacheStorage record bytes. path is used for provenance,
// the cache ID, and external body lookup. Unexpected panics are returned as ErrParserPanic.
func ParseCacheStorageRecordBytes(path string, raw []byte, salt []byte, opts BodyOptions) (rec *CacheStorageRecord, err error) {
	defer recoverAsError(&err, path)
	meta, err := decodeRecordMetaData(raw)
	if err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}

	// Records/<partitionHash>/<uniqueName>/<hash>: WebKit stores the cache uniqueName as Key.type.
	cacheID := meta.key.Type
	if cacheID == "" {
		cacheID = filepath.Base(filepath.Dir(path))
	}
	rec = &CacheStorageRecord{
		Path:              path,
		CacheID:           cacheID,
		Version:           meta.version,
		Key:               meta.key,
		Timestamp:         persist.WallTimeFromSeconds(meta.timestampRaw),
		MetaChecksumValid: meta.metaChecksumValid,
	}
	if !meta.metaChecksumValid {
		rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "meta_checksum_mismatch", Detail: "CacheStorage metadata checksum failed", Path: path})
	}

	hdrStart, hdrEnd, ok := headerBounds(len(raw), meta.headerOffset, meta.headerSize)
	if !ok {
		rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "truncated_header", Detail: fmt.Sprintf("header (offset %d, size %d) extends past file size %d", meta.headerOffset, meta.headerSize, len(raw)), Path: path})
		return rec, nil
	}
	hdrBytes := raw[hdrStart:hdrEnd]

	if len(salt) > 0 {
		hMatch := ComputeSaltedSHA1(salt, hdrBytes) == meta.headerHash
		rec.HeaderHashValid = &hMatch
		if !hMatch {
			rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "header_hash_mismatch", Detail: "CacheStorage salted header SHA-1 mismatch", Path: path})
		}
	}

	if meta.version < 16 || meta.version > 19 {
		rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "unsupported_version", Detail: fmt.Sprintf("CacheStorage version %d (supported: 16-19)", meta.version), Path: path})
	} else {
		decodeCacheStorageHeaderInto(rec, hdrBytes)
	}

	var contentEnc, declaredMIME string
	if rec.Response != nil {
		contentEnc = rec.Response.HeaderValue("Content-Encoding")
		declaredMIME = rec.Response.MIMEType
	}

	if meta.bodySize > 0 || meta.isBodyInline {
		var bodyRaw []byte
		storage := "inline"
		if meta.isBodyInline {
			if bodyEnd, ok := inlineBodyEnd(len(raw), hdrEnd, meta.bodySize); ok {
				bodyRaw = raw[hdrEnd:bodyEnd]
				if extra := len(raw) - bodyEnd; extra > 0 {
					rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "trailing_data", Detail: fmt.Sprintf("%d bytes after inline body; WebKit requires the body to end at EOF", extra), Path: path})
				}
			} else {
				storage = "missing"
				rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "truncated_body", Detail: fmt.Sprintf("inline body (size %d) extends past file size %d", meta.bodySize, len(raw)), Path: path})
			}
		} else {
			storage = "blob"
			b, err := readExternal(path, strings.ToUpper(hex.EncodeToString(meta.bodyHash[:])))
			if err != nil {
				storage = "missing"
				rec.Anomalies = append(rec.Anomalies, blobError(err, path))
			} else {
				bodyRaw = b
			}
		}
		if storage != "missing" {
			if uint64(len(bodyRaw)) != meta.bodySize {
				rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "body_size_mismatch", Detail: fmt.Sprintf("body has %d bytes; metadata declares %d", len(bodyRaw), meta.bodySize), Path: path})
			}
			if len(salt) > 0 && meta.bodySize > 0 {
				bMatch := ComputeSaltedSHA1(salt, bodyRaw) == meta.bodyHash
				rec.BodyHashValid = &bMatch
				if !bMatch {
					rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "body_hash_mismatch", Detail: fmt.Sprintf("salted body SHA-1 mismatch (expected %s)", strings.ToUpper(hex.EncodeToString(meta.bodyHash[:]))), Path: path})
				}
			}
			if len(bodyRaw) > 0 {
				bi := AnalyzeBody(storage, bodyRaw, contentEnc, declaredMIME, opts)
				rec.Body = &bi
				appendExportError(&rec.Anomalies, bi, path)
				if a := truncatedBodyAnomaly(&bi, path); a != nil {
					rec.Anomalies = append(rec.Anomalies, *a)
				}
			}
		}
	}

	return rec, nil
}

type cacheStorageProfile struct {
	legacyCertType    bool
	hasPrivateRelayed bool
	hasProxyName      bool
}

func cacheStorageProfiles(version uint32) []cacheStorageProfile {
	if version >= 19 {
		return []cacheStorageProfile{{legacyCertType: false, hasPrivateRelayed: true, hasProxyName: true}}
	}
	if version == 16 {
		return []cacheStorageProfile{
			{legacyCertType: false, hasPrivateRelayed: true, hasProxyName: true},
			{legacyCertType: false, hasPrivateRelayed: true, hasProxyName: false},
			{legacyCertType: true, hasPrivateRelayed: false, hasProxyName: false},
			{legacyCertType: false, hasPrivateRelayed: false, hasProxyName: false},
		}
	}
	return []cacheStorageProfile{
		{legacyCertType: false, hasPrivateRelayed: true, hasProxyName: true},
		{legacyCertType: false, hasPrivateRelayed: true, hasProxyName: false},
	}
}

type decodedCacheStorageHeader struct {
	insertionTime    time.Time
	requestGuard     string
	request          *ResourceRequest
	fetchOptions     *FetchOptions
	referrer         string
	responseGuard    string
	response         *ResourceResponse
	responseBodySize uint64
	checksumValid    bool
	remaining        int
}

func tryDecodeCacheStorageHeader(hdrBytes []byte, version uint32, prof cacheStorageProfile) (*decodedCacheStorageHeader, error) {
	dec := persist.NewDecoder(hdrBytes)
	insTime, _, err := dec.WallTime()
	if err != nil {
		return nil, fmt.Errorf("insertionTime: %w", err)
	}
	if _, err := dec.Uint64(); err != nil { // record size
		return nil, fmt.Errorf("size: %w", err)
	}
	reqGuard, err := dec.Enum()
	if err != nil {
		return nil, fmt.Errorf("requestHeadersGuard: %w", err)
	}
	req, err := decodeResourceRequest(dec)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	fo, err := decodeFetchOptions(dec)
	if err != nil {
		return nil, fmt.Errorf("fetchOptions: %w", err)
	}
	ref, err := dec.StringValue()
	if err != nil {
		return nil, fmt.Errorf("referrer: %w", err)
	}
	respGuard, err := dec.Enum()
	if err != nil {
		return nil, fmt.Errorf("responseHeadersGuard: %w", err)
	}
	isNull, err := dec.Bool()
	if err != nil || isNull {
		return nil, fmt.Errorf("null or invalid response marker")
	}
	resp, err := decodeResourceResponseData(dec, version, prof)
	if err != nil {
		return nil, fmt.Errorf("responseData: %w", err)
	}
	bodySize, err := dec.Uint64()
	if err != nil {
		return nil, fmt.Errorf("responseBodySize: %w", err)
	}
	ok, err := dec.VerifyChecksum()
	if err != nil {
		return nil, fmt.Errorf("checksum: %w", err)
	}
	return &decodedCacheStorageHeader{
		insertionTime:    insTime,
		requestGuard:     enumName(reqGuard, fetchGuardNames),
		request:          req,
		fetchOptions:     fo,
		referrer:         ref,
		responseGuard:    enumName(respGuard, fetchGuardNames),
		response:         resp,
		responseBodySize: bodySize,
		checksumValid:    ok,
		remaining:        dec.Remaining(),
	}, nil
}

func decodeCacheStorageHeaderInto(rec *CacheStorageRecord, hdrBytes []byte) {
	var fallback *decodedCacheStorageHeader
	var firstErr error
	for _, prof := range cacheStorageProfiles(rec.Version) {
		res, err := tryDecodeCacheStorageHeader(hdrBytes, rec.Version, prof)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if res.checksumValid && res.remaining == 0 {
			applyCacheStorageHeader(rec, res)
			return
		}
		if fallback == nil {
			fallback = res
		}
	}
	if fallback != nil {
		applyCacheStorageHeader(rec, fallback)
		return
	}
	if firstErr != nil {
		rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "header_decode_error", Detail: firstErr.Error(), Path: rec.Path})
	}
}

func applyCacheStorageHeader(rec *CacheStorageRecord, res *decodedCacheStorageHeader) {
	rec.InsertionTime = res.insertionTime
	rec.RequestGuard = res.requestGuard
	rec.Request = res.request
	rec.FetchOptions = res.fetchOptions
	rec.Referrer = res.referrer
	rec.ResponseGuard = res.responseGuard
	rec.Response = res.response
	rec.ResponseBodySize = res.responseBodySize
	ok := res.checksumValid && res.remaining == 0
	rec.HeaderChecksumValid = &ok
	if !ok {
		rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "header_checksum_mismatch", Detail: "CacheStorage header persistence checksum failed", Path: rec.Path})
	}
}

func decodeFetchOptions(dec *persist.Decoder) (*FetchOptions, error) {
	dest, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	mode, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	creds, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	cache, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	redir, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	refPol, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	integrity, err := dec.StringValue()
	if err != nil {
		return nil, err
	}
	keepAlive, err := dec.Bool()
	if err != nil {
		return nil, err
	}
	return &FetchOptions{
		Destination:    enumName(dest, fetchDestNames),
		Mode:           enumName(mode, fetchModeNames),
		Credentials:    enumName(creds, fetchCredentialsNames),
		Cache:          enumName(cache, fetchCacheNames),
		Redirect:       enumName(redir, fetchRedirectNames),
		ReferrerPolicy: enumName(refPol, referrerPolicyNames),
		Integrity:      integrity,
		KeepAlive:      keepAlive,
	}, nil
}

// decodeResourceResponseData handles CacheStorageDiskStore v16, v17, v18, and v19 layouts
// verified against WebKit commits f553e9880c, 5a98869830, and f46d7d8c34.
func decodeResourceResponseData(dec *persist.Decoder, version uint32, prof cacheStorageProfile) (*ResourceResponse, error) {
	urlStr, err := dec.StringValue()
	if err != nil {
		return nil, err
	}
	mime, err := dec.StringValue()
	if err != nil {
		return nil, err
	}
	expLen, err := dec.Int64()
	if err != nil {
		return nil, err
	}
	textEnc, err := dec.StringValue()
	if err != nil {
		return nil, err
	}
	statusText, err := dec.StringValue()
	if err != nil {
		return nil, err
	}
	httpVer, err := dec.StringValue()
	if err != nil {
		return nil, err
	}
	headers, err := decodeHTTPHeaderMap(dec)
	if err != nil {
		return nil, err
	}
	statusCode, err := dec.Int16()
	if err != nil {
		return nil, err
	}
	certs, err := decodeOptionalCertificateInfo(dec, prof.legacyCertType)
	if err != nil {
		return nil, err
	}
	src, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	typ, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	taint, err := dec.Enum()
	if err != nil {
		return nil, err
	}

	resp := &ResourceResponse{
		URL:                   urlStr,
		MIMEType:              mime,
		ExpectedContentLength: expLen,
		TextEncoding:          textEnc,
		HTTPStatusCode:        statusCode,
		HTTPStatusText:        statusText,
		HTTPVersion:           httpVer,
		Headers:               headers,
		Certificates:          certs,
		Source:                enumName(src, responseSourceNames),
		Type:                  enumName(typ, responseTypeNames),
		Tainting:              enumName(taint, responseTaintingNames),
	}

	if version >= 19 {
		if resp.ProxyName, err = dec.StringValue(); err != nil {
			return nil, err
		}
		ip, err := dec.Enum()
		if err != nil {
			return nil, err
		}
		resp.IPAddressSpace = enumName(ip, ipAddressSpaceNames)
		rawFlags, err := dec.Uint32()
		if err != nil {
			return nil, err
		}
		resp.IsRedirected = (rawFlags & (1 << 0)) != 0
		resp.UsedLegacyTLS = (rawFlags & (1 << 1)) != 0
		resp.WasPrivateRelayed = (rawFlags & (1 << 2)) != 0
		resp.IsRangeRequested = (rawFlags & (1 << 3)) != 0
		inc := (rawFlags & (1 << 4)) != 0
		resp.IncludesCredentials = &inc
		return resp, nil
	}

	// v16, v17, v18 layout.
	if resp.IsRedirected, err = dec.Bool(); err != nil {
		return nil, err
	}
	legacyTLS, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	resp.UsedLegacyTLS = legacyTLS != 0
	if prof.hasPrivateRelayed {
		privRelay, err := dec.Enum()
		if err != nil {
			return nil, err
		}
		resp.WasPrivateRelayed = privRelay != 0
	}
	if prof.hasProxyName {
		if resp.ProxyName, err = dec.StringValue(); err != nil {
			return nil, err
		}
	}
	if resp.IsRangeRequested, err = dec.Bool(); err != nil {
		return nil, err
	}
	if version >= 17 {
		ip, err := dec.Enum()
		if err != nil {
			return nil, err
		}
		resp.IPAddressSpace = enumName(ip, ipAddressSpaceNames)
	}
	if version >= 18 {
		incVal, err := dec.Enum()
		if err != nil {
			return nil, err
		}
		inc := incVal != 0
		resp.IncludesCredentials = &inc
	}
	return resp, nil
}

// ScanCacheStorageStore scans a CacheStorage/Version <N> directory.
func ScanCacheStorageStore(versionDir string, opts BodyOptions) (*CacheStorageStore, error) {
	store := &CacheStorageStore{Root: versionDir}
	// WebKit writes the 8-byte origin salt inside Version <N>/salt or next to cacheslist
	// in the enclosing CacheStorage/ directory.
	salt := storeSalt(versionDir, true)
	store.SaltPresent = salt != nil
	if salt == nil {
		store.Anomalies = append(store.Anomalies, Anomaly{Code: "missing_salt", Detail: "salt missing or invalid; salted SHA-1 verification skipped", Path: versionDir})
	}

	// The cacheslist file lives next to the Version directory and maps uniqueName -> cache name.
	names, err := ReadCachesList(filepath.Join(filepath.Dir(versionDir), "cacheslist"))
	if err != nil {
		store.Anomalies = append(store.Anomalies, Anomaly{Code: "cacheslist_parse_error", Detail: err.Error(), Path: filepath.Join(filepath.Dir(versionDir), "cacheslist")})
	}
	store.CacheNames = names

	recordsRoot := filepath.Join(versionDir, "Records")
	_ = filepath.WalkDir(recordsRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if path != recordsRoot || !os.IsNotExist(err) {
				store.Anomalies = append(store.Anomalies, Anomaly{Code: "walk_error", Detail: err.Error(), Path: path})
			}
			return nil
		}
		if d.IsDir() || !isHex40(d.Name()) {
			return nil
		}
		rec, err := ParseCacheStorageRecord(path, salt, opts)
		if err != nil {
			store.Anomalies = append(store.Anomalies, Anomaly{Code: parseErrorCode(err, "cachestorage_parse_error"), Detail: err.Error(), Path: path})
			return nil
		}
		if n, ok := names[rec.CacheID]; ok {
			rec.CacheName = n
		}
		store.Records = append(store.Records, *rec)
		return nil
	})
	if store.Records == nil {
		store.Records = []CacheStorageRecord{}
	}
	return store, nil
}

// ReadCachesList decodes a CacheStorage cacheslist file (uint64 count, then name/uniqueName
// string pairs) into a uniqueName -> name map. A missing file returns (nil, nil).
func ReadCachesList(path string) (out map[string]string, err error) {
	defer recoverAsError(&err, path)
	raw, err := evidence.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	dec := persist.NewDecoder(raw)
	count, err := dec.Uint64()
	if err != nil {
		return nil, fmt.Errorf("count: %w", err)
	}
	if count > 100000 {
		return nil, fmt.Errorf("unreasonable cache count %d", count)
	}
	out = make(map[string]string, count)
	for i := uint64(0); i < count; i++ {
		name, err := dec.StringValue()
		if err != nil {
			return out, fmt.Errorf("name %d: %w", i, err)
		}
		unique, err := dec.StringValue()
		if err != nil {
			return out, fmt.Errorf("uniqueName %d: %w", i, err)
		}
		out[unique] = name
	}
	return out, nil
}
