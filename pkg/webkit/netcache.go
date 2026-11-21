package webkit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/0x4d31/wkparse/internal/evidence"
	"github.com/0x4d31/wkparse/pkg/persist"
)

type recordMetaData struct {
	version           uint32
	key               Key
	timestampRaw      float64
	headerHash        [20]byte
	headerSize        uint64
	bodyHash          [20]byte
	bodySize          uint64
	isBodyInline      bool
	metaChecksumValid bool
	headerOffset      int
}

func decodeRecordMetaData(data []byte) (*recordMetaData, error) {
	dec := persist.NewDecoder(data)
	ver, err := dec.Uint32()
	if err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	key, err := decodeKey(dec)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	_, tsRaw, err := dec.WallTime()
	if err != nil {
		return nil, fmt.Errorf("timeStamp: %w", err)
	}
	hdrHash, err := dec.SHA1Digest()
	if err != nil {
		return nil, fmt.Errorf("headerHash: %w", err)
	}
	hdrSize, err := dec.Uint64()
	if err != nil {
		return nil, fmt.Errorf("headerSize: %w", err)
	}
	bodyHash, err := dec.SHA1Digest()
	if err != nil {
		return nil, fmt.Errorf("bodyHash: %w", err)
	}
	bodySize, err := dec.Uint64()
	if err != nil {
		return nil, fmt.Errorf("bodySize: %w", err)
	}
	isInline, err := dec.Bool()
	if err != nil {
		return nil, fmt.Errorf("isBodyInline: %w", err)
	}
	ok, err := dec.VerifyChecksum()
	if err != nil {
		return nil, fmt.Errorf("metadata checksum: %w", err)
	}
	return &recordMetaData{
		version:           ver,
		key:               key,
		timestampRaw:      tsRaw,
		headerHash:        hdrHash,
		headerSize:        hdrSize,
		bodyHash:          bodyHash,
		bodySize:          bodySize,
		isBodyInline:      isInline,
		metaChecksumValid: ok,
		headerOffset:      dec.Offset(),
	}, nil
}

func decodeKey(dec *persist.Decoder) (Key, error) {
	partition, err := dec.StringValue()
	if err != nil {
		return Key{}, err
	}
	typ, err := dec.StringValue()
	if err != nil {
		return Key{}, err
	}
	id, err := dec.StringValue()
	if err != nil {
		return Key{}, err
	}
	rng, err := dec.StringValue()
	if err != nil {
		return Key{}, err
	}
	hashBytes, err := dec.SHA1Digest()
	if err != nil {
		return Key{}, err
	}
	partHash, err := dec.SHA1Digest()
	if err != nil {
		return Key{}, err
	}
	return Key{
		Partition:     partition,
		Type:          typ,
		Identifier:    id,
		Range:         rng,
		Hash:          strings.ToUpper(hex.EncodeToString(hashBytes[:])),
		PartitionHash: strings.ToUpper(hex.EncodeToString(partHash[:])),
	}, nil
}

func decodeHTTPHeaderMap(dec *persist.Decoder) ([]Header, error) {
	n, err := dec.Uint64()
	if err != nil {
		return nil, err
	}
	if n > 2048 {
		return nil, fmt.Errorf("unreasonable header count %d", n)
	}
	out := make([]Header, 0, n)
	for i := uint64(0); i < n; i++ {
		k, err := dec.StringValue()
		if err != nil {
			return nil, err
		}
		v, err := dec.StringValue()
		if err != nil {
			return nil, err
		}
		out = append(out, Header{Name: k, Value: v})
	}
	return out, nil
}

type resourceHeaderProfile struct {
	legacyCertType    bool
	hasPrivateRelayed bool
	hasIPAddressSpace bool
}

func resourceHeaderProfiles(version uint32) []resourceHeaderProfile {
	switch version {
	case 16:
		return []resourceHeaderProfile{
			{legacyCertType: true, hasPrivateRelayed: false},  // iOS 15–16.3
			{legacyCertType: false, hasPrivateRelayed: false}, // transitional v16 (post-3375bc1aa4, pre-0abef5e069)
			{legacyCertType: false, hasPrivateRelayed: true},  // iOS 16.4+ / late v16
			{legacyCertType: true, hasPrivateRelayed: true},
		}
	case 17:
		return []resourceHeaderProfile{
			{legacyCertType: false, hasPrivateRelayed: true},
			{legacyCertType: false, hasPrivateRelayed: true, hasIPAddressSpace: true},
			{legacyCertType: false, hasPrivateRelayed: false},
		}
	default: // 18+
		return []resourceHeaderProfile{
			{legacyCertType: false, hasPrivateRelayed: true, hasIPAddressSpace: true},
			{legacyCertType: false, hasPrivateRelayed: true, hasIPAddressSpace: false},
		}
	}
}

func decodeResourceResponse(dec *persist.Decoder, prof resourceHeaderProfile) (*ResourceResponse, error) {
	isNull, err := dec.Bool()
	if err != nil {
		return nil, err
	}
	if isNull {
		return &ResourceResponse{IsNull: true}, nil
	}
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
		return nil, fmt.Errorf("certificateInfo: %w", err)
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
	isRedir, err := dec.Bool()
	if err != nil {
		return nil, err
	}
	legacyTLS, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	var privRelay uint64
	if prof.hasPrivateRelayed {
		privRelay, err = dec.Enum()
		if err != nil {
			return nil, err
		}
	}
	isRange, err := dec.Bool()
	if err != nil {
		return nil, err
	}
	var ipSpace string
	if prof.hasIPAddressSpace {
		v, err := dec.Enum()
		if err != nil {
			return nil, fmt.Errorf("ipAddressSpace: %w", err)
		}
		ipSpace = enumName(v, ipAddressSpaceNames)
	}
	return &ResourceResponse{
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
		IsRedirected:          isRedir,
		UsedLegacyTLS:         legacyTLS != 0,
		WasPrivateRelayed:     privRelay != 0,
		IsRangeRequested:      isRange,
		IPAddressSpace:        ipSpace,
	}, nil
}

func decodeResourceRequest(dec *persist.Decoder) (*ResourceRequest, error) {
	urlStr, err := dec.StringValue()
	if err != nil {
		return nil, err
	}
	timeout, err := dec.Float64()
	if err != nil {
		return nil, err
	}
	firstParty, err := dec.StringValue()
	if err != nil {
		return nil, err
	}
	method, err := dec.StringValue()
	if err != nil {
		return nil, err
	}
	headers, err := decodeHTTPHeaderMap(dec)
	if err != nil {
		return nil, err
	}
	fbCount, err := dec.Uint64()
	if err != nil {
		return nil, err
	}
	if fbCount > 64 {
		return nil, fmt.Errorf("unreasonable encoding fallback count %d", fbCount)
	}
	fallbacks := make([]string, 0, fbCount)
	for i := uint64(0); i < fbCount; i++ {
		s, err := dec.StringValue()
		if err != nil {
			return nil, err
		}
		fallbacks = append(fallbacks, s)
	}
	cachePolicy, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	allowCookies, err := dec.Bool()
	if err != nil {
		return nil, err
	}
	sameSite, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	isTopSite, err := dec.Bool()
	if err != nil {
		return nil, err
	}
	priority, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	requester, err := dec.Enum()
	if err != nil {
		return nil, err
	}
	isAppInit, err := dec.Bool()
	if err != nil {
		return nil, err
	}
	return &ResourceRequest{
		URL:                  urlStr,
		TimeoutInterval:      persist.SanitizeFloat(timeout),
		FirstPartyForCookies: firstParty,
		HTTPMethod:           method,
		Headers:              headers,
		EncodingFallbacks:    fallbacks,
		CachePolicy:          enumName(cachePolicy, cachePolicyNames),
		AllowCookies:         allowCookies,
		SameSiteDisposition:  enumName(sameSite, sameSiteNames),
		IsTopSite:            isTopSite,
		Priority:             enumName(priority, priorityNames),
		Requester:            enumName(requester, requesterNames),
		IsAppInitiated:       isAppInit,
	}, nil
}

func decodeSubresourcesHeader(data []byte) ([]SubresourceInfo, bool, error) {
	dec := persist.NewDecoder(data)
	count, err := dec.Uint64()
	if err != nil {
		return nil, false, err
	}
	if count > 10000 {
		return nil, false, fmt.Errorf("unreasonable subresource count %d", count)
	}
	out := make([]SubresourceInfo, 0, count)
	for i := uint64(0); i < count; i++ {
		key, err := decodeKey(dec)
		if err != nil {
			return nil, false, err
		}
		lastSeen, _, err := dec.WallTime()
		if err != nil {
			return nil, false, err
		}
		firstSeen, _, err := dec.WallTime()
		if err != nil {
			return nil, false, err
		}
		isTransient, err := dec.Bool()
		if err != nil {
			return nil, false, err
		}
		info := SubresourceInfo{
			Key:         key,
			LastSeen:    lastSeen,
			FirstSeen:   firstSeen,
			IsTransient: isTransient,
		}
		if !isTransient {
			if info.IsSameSite, err = dec.Bool(); err != nil {
				return nil, false, err
			}
			if info.IsAppInitiated, err = dec.Bool(); err != nil {
				return nil, false, err
			}
			if info.FirstPartyForCookies, err = dec.StringValue(); err != nil {
				return nil, false, err
			}
			if info.RequestHeaders, err = decodeHTTPHeaderMap(dec); err != nil {
				return nil, false, err
			}
			prio, err := dec.Enum()
			if err != nil {
				return nil, false, err
			}
			info.Priority = enumName(prio, priorityNames)
		}
		out = append(out, info)
	}
	ok, err := dec.VerifyChecksum()
	if err != nil {
		return out, false, err
	}
	return out, ok && dec.Remaining() == 0, nil
}

// ParseNetworkCacheRecord decodes a single NetworkCache record file (and sibling -blob if present).
func ParseNetworkCacheRecord(path string, salt []byte, opts BodyOptions) (*NetworkCacheRecord, error) {
	raw, err := evidence.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseNetworkCacheRecordBytes(path, raw, salt, opts)
}

// ParseNetworkCacheRecordBytes decodes NetworkCache record bytes. path is used for provenance
// and to locate an external body (path+"-blob" or <store>/Blobs/<bodyHash>).
// It never panics on malformed input; unexpected panics are returned as ErrParserPanic.
func ParseNetworkCacheRecordBytes(path string, raw []byte, salt []byte, opts BodyOptions) (rec *NetworkCacheRecord, err error) {
	defer recoverAsError(&err, path)
	meta, err := decodeRecordMetaData(raw)
	if err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}

	rec = &NetworkCacheRecord{
		Path:              path,
		Version:           meta.version,
		Key:               meta.key,
		Timestamp:         persist.WallTimeFromSeconds(meta.timestampRaw),
		RawTimestamp:      persist.SanitizeFloat(meta.timestampRaw),
		HeaderSize:        meta.headerSize,
		BodySize:          meta.bodySize,
		IsBodyInline:      meta.isBodyInline,
		HeaderHash:        strings.ToUpper(hex.EncodeToString(meta.headerHash[:])),
		BodyHash:          strings.ToUpper(hex.EncodeToString(meta.bodyHash[:])),
		MetaChecksumValid: meta.metaChecksumValid,
	}
	if !meta.metaChecksumValid {
		rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "meta_checksum_mismatch", Detail: "WTF::Persistence metadata checksum failed", Path: path})
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
			rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "header_hash_mismatch", Detail: "salted SHA-1 of header does not match metadata", Path: path})
		}
	}

	switch meta.key.Type {
	case "Resource":
		if meta.version < 16 || meta.version > 18 {
			rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "unsupported_version", Detail: fmt.Sprintf("NetworkCache version %d (supported: 16-18)", meta.version), Path: path})
		} else {
			decodeResourceHeaderInto(rec, hdrBytes)
		}
	case "SubResources":
		subs, ok, err := decodeSubresourcesHeader(hdrBytes)
		if err != nil {
			rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "subresources_decode_error", Detail: err.Error(), Path: path})
		} else {
			rec.Subresources = subs
			rec.HeaderChecksumValid = &ok
			if !ok {
				rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "header_checksum_mismatch", Detail: "SubResources persistence checksum failed", Path: path})
			}
		}
	}

	// Body extraction (inline or external -blob file).
	var contentEnc, declaredMIME string
	if rec.Response != nil {
		contentEnc = rec.Response.HeaderValue("Content-Encoding")
		declaredMIME = rec.Response.MIMEType
		if declaredMIME == "" {
			declaredMIME = rec.Response.HeaderValue("Content-Type")
		}
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
			b, err := readExternal(path, rec.BodyHash)
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
					rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "body_hash_mismatch", Detail: "salted SHA-1 of body does not match metadata", Path: path})
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

// findNetworkCacheRoot walks upward from a record path to find its enclosing "Version <N>" directory.
func findNetworkCacheRoot(recordPath string) string {
	dir := filepath.Dir(recordPath)
	for i := 0; i < 6; i++ {
		if strings.HasPrefix(filepath.Base(dir), "Version ") {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// FindSaltForRecord locates the enclosing NetworkCache store's 8-byte salt file if present.
func FindSaltForRecord(recordPath string) []byte {
	root := findNetworkCacheRoot(recordPath)
	if root == "" {
		return nil
	}
	return storeSalt(root, strings.Contains("/"+filepath.ToSlash(root)+"/", "/CacheStorage/"))
}

func storeSalt(root string, cacheStorage bool) []byte {
	dirs := []string{root}
	if cacheStorage {
		dirs = []string{filepath.Dir(root), root}
	}
	for _, dir := range dirs {
		if b, err := evidence.ReadSalt(filepath.Join(dir, "salt")); err == nil {
			return b
		}
	}
	return nil
}

type decodedResourceHeader struct {
	response       *ResourceResponse
	varyHeaders    []Header
	isRedirect     bool
	privateRelayed bool
	redirectReq    *ResourceRequest
	maxAgeCap      *float64
	checksumValid  bool
	remaining      int
}

func tryDecodeResourceHeader(hdrBytes []byte, prof resourceHeaderProfile) (*decodedResourceHeader, error) {
	dec := persist.NewDecoder(hdrBytes)
	resp, err := decodeResourceResponse(dec, prof)
	if err != nil {
		return nil, fmt.Errorf("ResourceResponse: %w", err)
	}
	res := &decodedResourceHeader{response: resp}

	hasVary, err := dec.Bool()
	if err != nil {
		return nil, fmt.Errorf("hasVaryingRequestHeaders: %w", err)
	}
	if hasVary {
		n, err := dec.Uint64()
		if err != nil || n > 512 {
			return nil, fmt.Errorf("invalid vary header count")
		}
		for i := uint64(0); i < n; i++ {
			k, err := dec.StringValue()
			if err != nil {
				return nil, fmt.Errorf("vary header key: %w", err)
			}
			v, err := dec.StringValue()
			if err != nil {
				return nil, fmt.Errorf("vary header value: %w", err)
			}
			res.varyHeaders = append(res.varyHeaders, Header{Name: k, Value: v})
		}
	}

	flags, err := dec.Uint8()
	if err != nil {
		return nil, fmt.Errorf("flags: %w", err)
	}
	res.isRedirect = (flags & 0x1) != 0
	res.privateRelayed = (flags & 0x2) != 0

	if res.isRedirect {
		// NetworkCacheEntry encodes std::optional<ResourceRequest> inside if (isRedirect).
		engaged, err := dec.Bool()
		if err != nil {
			return nil, fmt.Errorf("redirectRequest flag: %w", err)
		}
		if engaged {
			rr, err := decodeResourceRequest(dec)
			if err != nil {
				return nil, fmt.Errorf("redirectRequest: %w", err)
			}
			res.redirectReq = rr
		}
	}

	hasMaxAge, err := dec.Bool()
	if err != nil {
		return nil, fmt.Errorf("maxAgeCap flag: %w", err)
	}
	if hasMaxAge {
		secs, err := dec.Float64()
		if err != nil {
			return nil, fmt.Errorf("maxAgeCap: %w", err)
		}
		if !math.IsNaN(secs) && !math.IsInf(secs, 0) {
			res.maxAgeCap = &secs
		}
	}

	ok, err := dec.VerifyChecksum()
	if err != nil {
		return nil, fmt.Errorf("header checksum: %w", err)
	}
	res.checksumValid = ok
	res.remaining = dec.Remaining()
	return res, nil
}

func decodeResourceHeaderInto(rec *NetworkCacheRecord, hdrBytes []byte) {
	profiles := resourceHeaderProfiles(rec.Version)
	var fallback *decodedResourceHeader
	var firstErr error

	for _, prof := range profiles {
		res, err := tryDecodeResourceHeader(hdrBytes, prof)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if res.checksumValid && res.remaining == 0 {
			applyResourceHeader(rec, res)
			return
		}
		if fallback == nil {
			fallback = res
		}
	}

	if fallback != nil {
		applyResourceHeader(rec, fallback)
		return
	}
	if firstErr != nil {
		rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "header_decode_error", Detail: firstErr.Error(), Path: rec.Path})
	}
}

func applyResourceHeader(rec *NetworkCacheRecord, res *decodedResourceHeader) {
	rec.Response = res.response
	rec.VaryHeaders = res.varyHeaders
	rec.IsRedirect = res.isRedirect
	rec.PrivateRelayed = res.privateRelayed
	rec.RedirectRequest = res.redirectReq
	rec.MaxAgeCapSeconds = res.maxAgeCap
	ok := res.checksumValid && res.remaining == 0
	rec.HeaderChecksumValid = &ok
	if !ok {
		rec.Anomalies = append(rec.Anomalies, Anomaly{Code: "header_checksum_mismatch", Detail: "Resource header WTF::Persistence checksum failed", Path: rec.Path})
	}
}

// ScanNetworkCacheStore scans a NetworkCache/Version <N> directory, including orphaned Blobs/.
func ScanNetworkCacheStore(versionDir string, opts BodyOptions) (*NetworkCacheStore, error) {
	store := &NetworkCacheStore{Root: versionDir}
	salt := storeSalt(versionDir, false)
	if salt != nil {
		store.SaltPresent = true
	} else {
		salt = nil
		store.Anomalies = append(store.Anomalies, Anomaly{
			Code:   "missing_salt",
			Detail: "salt file missing or invalid; salted SHA-1 verification skipped",
			Path:   versionDir,
		})
	}

	referencedBlobs := make(map[string]struct{})
	failedRecords := 0
	recordsRoot := filepath.Join(versionDir, "Records")
	_ = filepath.WalkDir(recordsRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if path != recordsRoot || !os.IsNotExist(err) {
				store.Anomalies = append(store.Anomalies, Anomaly{Code: "walk_error", Detail: err.Error(), Path: path})
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !isHex40(name) {
			return nil
		}
		rec, err := ParseNetworkCacheRecord(path, salt, opts)
		if err != nil {
			failedRecords++
			store.Anomalies = append(store.Anomalies, Anomaly{Code: parseErrorCode(err, "record_parse_error"), Detail: err.Error(), Path: path})
			return nil
		}
		if !rec.IsBodyInline && rec.BodyHash != "" {
			referencedBlobs[strings.ToUpper(rec.BodyHash)] = struct{}{}
		}
		store.Records = append(store.Records, *rec)
		return nil
	})

	if store.Records == nil {
		store.Records = []NetworkCacheRecord{}
	}

	// Blobs in Blobs/ not referenced by any record that parsed. Benign causes include pending
	// BlobStorage cleanup, hard links broken by the extraction, and records that failed to parse.
	blobsRoot := filepath.Join(versionDir, "Blobs")
	if fi, err := os.Lstat(blobsRoot); err == nil && !fi.IsDir() {
		store.Anomalies = append(store.Anomalies, Anomaly{Code: "walk_error", Detail: "Blobs is not a regular directory", Path: blobsRoot})
		return store, nil
	}
	if entries, err := os.ReadDir(blobsRoot); err == nil {
		unreferenced := 0
		for _, e := range entries {
			if e.IsDir() || !isHex40(e.Name()) {
				continue
			}
			hashName := strings.ToUpper(e.Name())
			if _, ok := referencedBlobs[hashName]; ok {
				continue
			}
			blobPath := filepath.Join(blobsRoot, e.Name())
			raw, err := evidence.ReadFile(blobPath)
			if err != nil {
				store.Anomalies = append(store.Anomalies, Anomaly{
					Code:   "blob_read_error",
					Detail: err.Error(),
					Path:   blobPath,
				})
				continue
			}
			ob := OrphanBlob{
				Path: blobPath,
				Hash: hashName,
				Body: AnalyzeBody("orphan_blob", raw, "", "", opts),
			}
			if fi, err := e.Info(); err == nil {
				ob.FSModTime = fi.ModTime().UTC()
				ob.Nlink = statNlink(fi)
			}
			unreferenced++
			store.OrphanBlobs = append(store.OrphanBlobs, ob)
			store.Anomalies = append(store.Anomalies, Anomaly{
				Code:   "unreferenced_blob",
				Detail: fmt.Sprintf("blob %s (%d bytes, mime=%s, nlink=%d) not referenced by any parsed record", hashName, len(raw), ob.Body.DetectedMIME, ob.Nlink),
				Path:   blobPath,
			})
			appendExportError(&store.Anomalies, ob.Body, blobPath)
			if a := truncatedBodyAnomaly(&ob.Body, blobPath); a != nil {
				store.Anomalies = append(store.Anomalies, *a)
			}
		}
		if unreferenced > 0 && failedRecords > 0 {
			store.Anomalies = append(store.Anomalies, Anomaly{
				Code:   "unreferenced_blob_caveat",
				Detail: fmt.Sprintf("%d record(s) in this store failed to parse; blobs they reference are reported as unreferenced", failedRecords),
				Path:   versionDir,
			})
		}
	} else if !os.IsNotExist(err) {
		store.Anomalies = append(store.Anomalies, Anomaly{Code: "walk_error", Detail: err.Error(), Path: blobsRoot})
	}

	return store, nil
}

func parseErrorCode(err error, fallback string) string {
	if errors.Is(err, ErrParserPanic) {
		return "parser_panic"
	}
	return fallback
}
