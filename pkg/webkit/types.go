// Package webkit decodes Apple WebKit's on-disk binary caches and origin files
// directly from WebKit's C++ persistence formats (NetworkCache, CacheStorage, ClientOrigin).
package webkit

import (
	"fmt"
	"regexp"
	"time"
)

// Anomaly records integrity, tampering, or coverage findings on a parsed artifact.
type Anomaly struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
	Path   string `json:"path,omitempty"`
}

// Header preserves HTTP header ordering and duplicate header names (e.g. Set-Cookie).
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Key matches WebKit::NetworkCache::Key.
type Key struct {
	Partition     string `json:"partition,omitempty"`
	Type          string `json:"type"`
	Identifier    string `json:"identifier"`
	Range         string `json:"range,omitempty"`
	Hash          string `json:"hash"`
	PartitionHash string `json:"partition_hash"`
}

// SecurityOrigin matches WebCore::SecurityOriginData.
type SecurityOrigin struct {
	Protocol string  `json:"protocol"`
	Host     string  `json:"host"`
	Port     *uint16 `json:"port,omitempty"`
}

func (o SecurityOrigin) String() string {
	if o.Protocol == "" && o.Host == "" {
		return ""
	}
	if o.Port != nil && *o.Port != 0 {
		return fmt.Sprintf("%s://%s:%d", o.Protocol, o.Host, *o.Port)
	}
	return fmt.Sprintf("%s://%s", o.Protocol, o.Host)
}

// ClientOrigin matches WebCore::ClientOrigin (WebsiteData/Default/*/*/origin).
type ClientOrigin struct {
	Path         string         `json:"path,omitempty"`
	TopOrigin    SecurityOrigin `json:"top_origin"`
	ClientOrigin SecurityOrigin `json:"client_origin"`
	CrossOrigin  bool           `json:"cross_origin"`
}

// CertSummary holds X.509 certificate metadata extracted from Cocoa SecTrustSerialize blobs.
type CertSummary struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	SANs      []string  `json:"sans,omitempty"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	SHA256    string    `json:"sha256"`
}

// ResourceResponse matches WebCore::ResourceResponse / ResourceResponseData.
type ResourceResponse struct {
	IsNull                bool          `json:"is_null,omitempty"`
	URL                   string        `json:"url"`
	MIMEType              string        `json:"mime_type,omitempty"`
	ExpectedContentLength int64         `json:"expected_content_length"`
	TextEncoding          string        `json:"text_encoding,omitempty"`
	HTTPStatusCode        int16         `json:"http_status_code"`
	HTTPStatusText        string        `json:"http_status_text,omitempty"`
	HTTPVersion           string        `json:"http_version,omitempty"`
	Headers               []Header      `json:"headers,omitempty"`
	Certificates          []CertSummary `json:"certificates,omitempty"`
	Source                string        `json:"source,omitempty"`
	Type                  string        `json:"type,omitempty"`
	Tainting              string        `json:"tainting,omitempty"`
	IsRedirected          bool          `json:"is_redirected,omitempty"`
	UsedLegacyTLS         bool          `json:"used_legacy_tls,omitempty"`
	WasPrivateRelayed     bool          `json:"was_private_relayed,omitempty"`
	ProxyName             string        `json:"proxy_name,omitempty"`
	IsRangeRequested      bool          `json:"is_range_requested,omitempty"`
	IPAddressSpace        string        `json:"ip_address_space,omitempty"`
	IncludesCredentials   *bool         `json:"includes_credentials,omitempty"`
}

// HeaderValue returns the first case-insensitive matching header value.
func (r *ResourceResponse) HeaderValue(name string) string {
	for _, h := range r.Headers {
		if equalASCIIFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// ResourceRequest matches WebCore::ResourceRequest persisted in redirects and CacheStorage.
type ResourceRequest struct {
	URL                  string   `json:"url"`
	TimeoutInterval      float64  `json:"timeout_interval,omitempty"`
	FirstPartyForCookies string   `json:"first_party_for_cookies,omitempty"`
	HTTPMethod           string   `json:"http_method,omitempty"`
	Headers              []Header `json:"headers,omitempty"`
	EncodingFallbacks    []string `json:"encoding_fallbacks,omitempty"`
	CachePolicy          string   `json:"cache_policy,omitempty"`
	AllowCookies         bool     `json:"allow_cookies"`
	SameSiteDisposition  string   `json:"same_site_disposition,omitempty"`
	IsTopSite            bool     `json:"is_top_site,omitempty"`
	Priority             string   `json:"priority,omitempty"`
	Requester            string   `json:"requester,omitempty"`
	IsAppInitiated       bool     `json:"is_app_initiated"`
}

// SubresourceInfo matches WebKit::NetworkCache::SubresourceInfo.
type SubresourceInfo struct {
	Key                  Key       `json:"key"`
	LastSeen             time.Time `json:"last_seen"`
	FirstSeen            time.Time `json:"first_seen"`
	IsTransient          bool      `json:"is_transient"`
	IsSameSite           bool      `json:"is_same_site,omitempty"`
	IsAppInitiated       bool      `json:"is_app_initiated,omitempty"`
	FirstPartyForCookies string    `json:"first_party_for_cookies,omitempty"`
	RequestHeaders       []Header  `json:"request_headers,omitempty"`
	Priority             string    `json:"priority,omitempty"`
}

// FetchOptions matches WebCore::FetchOptions persisted in CacheStorage.
type FetchOptions struct {
	Destination    string `json:"destination,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Credentials    string `json:"credentials,omitempty"`
	Cache          string `json:"cache,omitempty"`
	Redirect       string `json:"redirect,omitempty"`
	ReferrerPolicy string `json:"referrer_policy,omitempty"`
	Integrity      string `json:"integrity,omitempty"`
	KeepAlive      bool   `json:"keep_alive,omitempty"`
}

// BodyInfo describes an extracted or recovered cache body.
type BodyInfo struct {
	Storage         string `json:"storage"` // inline | blob | orphan_blob | missing
	RawSize         int64  `json:"raw_size"`
	DecodedSize     int64  `json:"decoded_size,omitempty"`
	ContentEncoding string `json:"content_encoding,omitempty"`
	Decompressed    bool   `json:"decompressed,omitempty"`
	RawSHA256       string `json:"raw_sha256,omitempty"`
	DecodedSHA256   string `json:"decoded_sha256,omitempty"`
	// DecodeTruncated is set when decompressed output reached BodyOptions.MaxDecompress.
	// DecodedSize, DecodedPrefixSHA256, Snippet, Matches and any export then cover only that prefix.
	DecodeTruncated     bool     `json:"decode_truncated,omitempty"`
	DecodedPrefixSHA256 string   `json:"decoded_prefix_sha256,omitempty"`
	DetectedMIME        string   `json:"detected_mime,omitempty"`
	Snippet             string   `json:"snippet,omitempty"`
	ExportPath          string   `json:"export_path,omitempty"`
	ExportError         string   `json:"export_error,omitempty"`
	Matches             []string `json:"matches,omitempty"`
}

// BodyOptions controls payload extraction, bounded decompression, and regex triage.
type BodyOptions struct {
	ExportDir         string
	ExportMatchesOnly bool  // with Match set, export only bodies that matched
	MaxDecompress     int64 // default 32 MiB
	SnippetBytes      int   // default 256
	Match             *regexp.Regexp
}

// NetworkCacheRecord represents a decoded WebKit NetworkCache record (Resource or SubResources).
type NetworkCacheRecord struct {
	Path                string            `json:"path"`
	Version             uint32            `json:"version"`
	Key                 Key               `json:"key"`
	Timestamp           time.Time         `json:"timestamp"`
	RawTimestamp        float64           `json:"raw_timestamp"`
	HeaderSize          uint64            `json:"header_size"`
	BodySize            uint64            `json:"body_size"`
	IsBodyInline        bool              `json:"is_body_inline"`
	HeaderHash          string            `json:"header_hash"`
	BodyHash            string            `json:"body_hash"`
	MetaChecksumValid   bool              `json:"meta_checksum_valid"`
	HeaderHashValid     *bool             `json:"header_hash_valid,omitempty"`
	HeaderChecksumValid *bool             `json:"header_checksum_valid,omitempty"`
	BodyHashValid       *bool             `json:"body_hash_valid,omitempty"`
	Response            *ResourceResponse `json:"response,omitempty"`
	VaryHeaders         []Header          `json:"vary_headers,omitempty"`
	IsRedirect          bool              `json:"is_redirect,omitempty"`
	PrivateRelayed      bool              `json:"private_relayed,omitempty"`
	RedirectRequest     *ResourceRequest  `json:"redirect_request,omitempty"`
	MaxAgeCapSeconds    *float64          `json:"max_age_cap_seconds,omitempty"`
	Subresources        []SubresourceInfo `json:"subresources,omitempty"`
	Body                *BodyInfo         `json:"body,omitempty"`
	Anomalies           []Anomaly         `json:"anomalies,omitempty"`
}

// OrphanBlob represents a file in Blobs/<salted-sha1> not referenced by any record that parsed.
// Unreferenced blobs have benign causes (pending WebKit BlobStorage cleanup, hard links broken
// by the extraction, records that failed to parse) and are not by themselves evidence of tampering.
type OrphanBlob struct {
	Path  string `json:"path"`
	Hash  string `json:"hash"`
	Nlink uint64 `json:"nlink,omitempty"`
	// FSModTime is the filesystem mtime of the blob as seen in the extraction. Depending on the
	// acquisition method it may reflect extraction time rather than device activity.
	FSModTime time.Time `json:"fs_mtime,omitempty"`
	Body      BodyInfo  `json:"body"`
}

// NetworkCacheStore is the scan result for one NetworkCache/Version <N> directory.
type NetworkCacheStore struct {
	Root        string               `json:"root"`
	SaltPresent bool                 `json:"salt_present"`
	Records     []NetworkCacheRecord `json:"records"`
	OrphanBlobs []OrphanBlob         `json:"orphan_blobs,omitempty"`
	Anomalies   []Anomaly            `json:"anomalies,omitempty"`
}

// CacheStorageRecord represents a decoded DOM/ServiceWorker CacheStorage record.
type CacheStorageRecord struct {
	Path string `json:"path"`
	// CacheID is the cache's uniqueName (a UUID) taken from the Records/<partition>/<uniqueName>/ path.
	CacheID string `json:"cache_id,omitempty"`
	// CacheName is the script-visible cache name, resolved from the origin's cacheslist file when present.
	CacheName           string            `json:"cache_name,omitempty"`
	Version             uint32            `json:"version"`
	Key                 Key               `json:"key"`
	Timestamp           time.Time         `json:"timestamp"`
	InsertionTime       time.Time         `json:"insertion_time"`
	RequestGuard        string            `json:"request_guard,omitempty"`
	Request             *ResourceRequest  `json:"request,omitempty"`
	FetchOptions        *FetchOptions     `json:"fetch_options,omitempty"`
	Referrer            string            `json:"referrer,omitempty"`
	ResponseGuard       string            `json:"response_guard,omitempty"`
	Response            *ResourceResponse `json:"response,omitempty"`
	ResponseBodySize    uint64            `json:"response_body_size"`
	MetaChecksumValid   bool              `json:"meta_checksum_valid"`
	HeaderHashValid     *bool             `json:"header_hash_valid,omitempty"`
	HeaderChecksumValid *bool             `json:"header_checksum_valid,omitempty"`
	BodyHashValid       *bool             `json:"body_hash_valid,omitempty"`
	Body                *BodyInfo         `json:"body,omitempty"`
	Anomalies           []Anomaly         `json:"anomalies,omitempty"`
}

// CacheStorageStore is the scan result for one CacheStorage/Version <N> directory.
type CacheStorageStore struct {
	Root        string               `json:"root"`
	SaltPresent bool                 `json:"salt_present"`
	CacheNames  map[string]string    `json:"cache_names,omitempty"` // uniqueName -> name from cacheslist
	Records     []CacheStorageRecord `json:"records"`
	Anomalies   []Anomaly            `json:"anomalies,omitempty"`
}

func equalASCIIFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func enumName(v uint64, names []string) string {
	if v < uint64(len(names)) {
		return names[v]
	}
	return fmt.Sprintf("unknown(%d)", v)
}

func isHex40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < 40; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

var (
	responseSourceNames = []string{
		"Unknown", "Network", "DiskCache", "DiskCacheAfterValidation",
		"MemoryCache", "MemoryCacheAfterValidation", "ServiceWorker",
		"LegacyApplicationCachePlaceholder", "DOMCache", "InspectorOverride",
	}
	responseTypeNames     = []string{"Basic", "Cors", "Default", "Error", "Opaque", "Opaqueredirect"}
	responseTaintingNames = []string{"Basic", "Cors", "Opaque", "Opaqueredirect"}
	ipAddressSpaceNames   = []string{"Public", "Local", "Loopback", "Unknown"}
	cachePolicyNames      = []string{
		"UseProtocolCachePolicy", "ReloadIgnoringCacheData", "ReturnCacheDataElseLoad",
		"ReturnCacheDataDontLoad", "DoNotUseAnyCache", "RefreshAnyCacheData",
	}
	sameSiteNames  = []string{"Unspecified", "SameSite", "CrossSite"}
	priorityNames  = []string{"VeryLow", "Low", "Medium", "High", "VeryHigh"}
	requesterNames = []string{
		"Unspecified", "Main", "XHR", "Fetch", "Media", "Model",
		"ImportScripts", "Ping", "Beacon", "EventSource",
	}
	fetchGuardNames       = []string{"None", "Immutable", "Request", "RequestNoCors", "Response"}
	fetchModeNames        = []string{"Navigate", "SameOrigin", "NoCors", "Cors"}
	fetchCredentialsNames = []string{"Omit", "SameOrigin", "Include"}
	fetchCacheNames       = []string{"Default", "NoStore", "Reload", "NoCache", "ForceCache", "OnlyIfCached"}
	fetchRedirectNames    = []string{"Follow", "Error", "Manual"}
	fetchDestNames        = []string{
		"", "audio", "audioworklet", "document", "embed", "environmentmap",
		"font", "image", "iframe", "json", "manifest", "model", "object",
		"paintworklet", "report", "script", "serviceworker", "sharedworker",
		"speculationrules", "style", "track", "video", "worker", "xslt",
		"text", "compressiondictionary",
	}
	referrerPolicyNames = []string{
		"", "no-referrer", "no-referrer-when-downgrade", "same-origin", "origin",
		"strict-origin", "origin-when-cross-origin", "strict-origin-when-cross-origin", "unsafe-url",
	}
)
