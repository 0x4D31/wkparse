# WebKit Forensic Format & Path Reference

This reference summarizes the on-disk binary and database formats decoded by `wkparse`, along with iOS/macOS locations and acquisition caveats.

## `WTF::Persistence` Binary Codec

WebKit serializes `NetworkCache`, `CacheStorage`, and `origin` files using `WTF::Persistence::Encoder` (little-endian primitives, no struct alignment padding).

- **Strings (`WTF::String`)**: `uint32` length (`0xFFFFFFFF` = null), `bool` `is8Bit`, then `length` Latin-1 bytes or `length * 2` UTF-16LE bytes.
- **Enums**: encoded as `uint64` via `encode<uint64_t>` in `PersistentCoders`.
- **Timestamps (`WallTime`)**: IEEE-754 `float64` seconds since the Unix epoch (`1970-01-01T00:00:00Z`). Zero, non-finite values and values outside the JSON timestamp range are treated as unset; representable negative Unix times are retained.
- **Integrity Checksum**: Every encoded metadata block and header block ends with a 20-byte SHA-1 digest. Before hashing each field's raw bytes, WebKit updates the SHA-1 state with a 4-byte little-endian type salt (`bool=3`, `uint8=5`, `uint16=7`, `uint32=11`, `uint64=13`, `int32=17`, `int64=19`, `float32=23`, `float64=29`, `bytes=101`, `int16=103`).

## `NetworkCache` (Versions 16–18)

Directory layout inside each app or daemon cache root:

```text
NetworkCache/Version <N>/
├── salt                                   # 8 random bytes for salted SHA-1 verification
├── Blobs/<40-hex BodyHash>                # Content-addressed external bodies (>16 KB)
└── Records/<PartitionHash>/<Type>/
    ├── <40-hex>                           # Metadata + header + optional inline body
    └── <40-hex>-blob                      # Hard link to Blobs/<BodyHash>
```

### Record Structure

1. **Metadata block**: `version` (`u32`), `Key` (`partition`, `type`, `identifier` URL, `range`, `hash[20]`, `partitionHash[20]`), `timeStamp` (`WallTime`), `headerHash[20]`, `headerSize` (`u64`), `bodyHash[20]`, `bodySize` (`u64`), `isBodyInline` (`bool`), and trailing 20-byte `WTF::Persistence` checksum.
2. **Header block (`headerSize` bytes)**:
   - `Type == "Resource"`: `ResourceResponse`, optional `Vary` header map, `flags` (`bit 0 = isRedirect`, `bit 1 = privateRelayed`), optional `RedirectRequest`, optional `maxAgeCap` (`f64`), and trailing 20-byte checksum.
   - `Type == "SubResources"`: list of `SubresourceInfo` entries linking a top-level page URL to each subresource URL with `firstSeen` and `lastSeen` timestamps.
3. **Body**: inline immediately after the header if `isBodyInline == true`, otherwise stored in `<record>-blob` (with fallback lookup in `Blobs/<BodyHash>` if hard links were not preserved during extraction). `wkparse` verifies salted `SHA1(salt || bytes)` against `headerHash` and `bodyHash`, decompresses `gzip`/`deflate`/`br` bodies (with a decompression cap), and computes decoded SHA-256 hashes.

### Version 16–18 Header Variants

WebKit changed `ResourceResponse` serialization several times without always bumping the store version:

| Variant | Store Version | Differences in `ResourceResponse` |
| :--- | :--- | :--- |
| iOS 15 – 16.3 | `Version 16` | `CertificateInfo` includes a legacy `uint64` type tag (`1=CertificateChain`, `2=Trust`); `wasPrivateRelayed` is absent |
| Transitional v16 | `Version 16` | Legacy `CertificateInfo` type tag removed (`3375bc1aa4`); `wasPrivateRelayed` still absent |
| iOS 16.4+ – 18 | `Version 16` / `17` | No legacy cert type tag; `wasPrivateRelayed` (`u64`) present (`0abef5e069`) |
| Newer WebKit | `Version 18` | Adds `IPAddressSpace` (`u64`: `Public`, `Local`, `Loopback`, `Unknown`) after `isRangeRequested` |

`wkparse` dispatches across candidate layouts for the record's version and prefers the layout whose trailing 20-byte `WTF::Persistence` SHA-1 checksum passes with zero unread bytes. If no layout verifies but a candidate decodes, it retains that candidate as best-effort output with `header_checksum_mismatch`; those fields are not verified.

### TLS Certificates (`SecTrustSerialize`)

When `CertificateInfo` is present in a cached response, Apple serializes the `SecTrustRef` via `SecTrustSerialize` into an ASN.1 DER structure (`SET` of key/value `SEQUENCE`s containing `OCTET STRING` DER X.509 certificates). `wkparse` walks the DER container (with a plist fallback), deduplicates certificates by SHA-256, and reports subject, issuer, SANs, validity window, and SHA-256 fingerprint.

### Unreferenced Blobs

`Blobs/<BodyHash>` files are hard-linked to `<record>-blob`. When a record is removed (normal eviction, cache clearing, or deliberate deletion) the blob can remain until WebKit's next shrink pass. `wkparse` compares every file in `Blobs/` against all surviving records' `bodyHash` values and reports unreferenced files as `unreferenced_blob` anomalies with file size, link count, detected MIME type, SHA-256, filesystem mtime (`fs_mtime`) and optional regex matches or export.

These are leads, not evidence of deletion. If any record in the same store failed to parse, `wkparse` adds an `unreferenced_blob_caveat`, because the failed record may have referenced the blob. The `fs_mtime` value depends on how the extraction preserved metadata.

## `CacheStorage` (Versions 16–19)

Service Worker `caches.open(...)` / `Cache.put(...)` storage. Records reuse the `NetworkCache` metadata framing and store `insertionTime`, `ResourceRequest`, `ResourceResponse`, request options and body storage.

Two layouts are recognized:

```text
# Current: per-origin directory under WebsiteData
<origin-dir>/CacheStorage/
├── cacheslist
└── Version <N>/Records/...

# Legacy: one hashed directory per origin
CacheStorage/<hex-origin-hash>/
├── cacheslist
└── Version <N>/Records/...
```

The record key's `type` field carries the cache's `uniqueName`, reported as `cache_id`. The human-readable name comes from `cacheslist`: a `uint64` count followed by `(name, uniqueName)` `WTF::String` pairs. When `cacheslist` is present, `wkparse` fills `cache_name` on each record; a malformed file produces a `cacheslist_parse_error` anomaly and records keep only `cache_id`.

## Unified Origin Storage (`origin`)

Under `WebsiteData/Default/<origin-hash>/origin` (and `WebsiteDataStore/...`), each binary `origin` file encodes `ClientOrigin` (`TopOrigin` + `ClientOrigin`, each `protocol`, `host`, optional `port`). When `TopOrigin != ClientOrigin`, `wkparse` marks `cross_origin: true` and adds a `cross_origin_client` edge to the graph.

## SQLite & Plist Stores

- **`observations.db`** (`ResourceLoadStatistics/` or `SafariViewService/Library/WebKit/WebsiteData/`): Source files are read without modification and copied (alongside `-wal` and `-shm`) into a private temporary snapshot. SQLite opens that copy normally so WAL recovery can occur there. A WAL file without its main database is reported as a coverage gap. Column sets differ across WebKit versions, so `ObservedDomains` is queried using whichever known columns exist and missing columns are reported as `itp_read_warning`. Parses `ObservedDomains`, `OperatingDates`, and all 10 relationship tables (`SubframeUnderTopFrameDomains`, `SubresourceUnderTopFrameDomains`, `SubresourceUniqueRedirectsTo`, `SubresourceUniqueRedirectsFrom`, `TopFrameLoadedThirdPartyScripts`, `TopFrameUniqueRedirectsTo`, `TopFrameUniqueRedirectsToSinceSameSiteStrictEnforcement`, `TopFrameUniqueRedirectsFrom`, `TopFrameLinkDecorationsFrom`, `StorageAccessUnderTopFrameDomains`).
- **`localstorage.sqlite3` / `*.localstorage`**: Parses `ItemTable` (`key`, `value`). WebKit's `SQLiteStorageArea` writes values with `SQLiteStatement::bindBlob(String)`, which stores the string as UTF-16LE, so blob values are decoded as UTF-16LE regardless of content. Values stored with SQLite type `text` (older or third-party writers) are decoded as UTF-8; odd-length blobs fall back to UTF-8 or hex. The origin comes from the sibling `origin` sidecar (current layout) or the `<scheme>_<host>_<port>.localstorage` filename (legacy).
- **`ServiceWorkerRegistrations-*.sqlite3`**: Parses `Records` (`origin`, `scopeURL`, `topOrigin`, `scriptURL`, `lastUpdateCheckTime`, `updateViaCache`, `workerType`, `referrerPolicy`). WebKit stores `scopeURL` as a path relative to `origin`, and `topOrigin` as a `<scheme>_<host>_<port>` database identifier. Output resolves these to URLs and retains `scope_path_raw` and `top_origin_raw`. Graph output includes same-origin and cross-origin registrations.
- **`HSTS.plist`**: Parses `CFNetwork` storage session dictionaries (`Host`, `Expiry`, `Include Subdomains`), retaining the `session` name. Policies for the same host in different sessions remain separate.
- **`MediaCache/diskcacherepository.plist`**: Parses `checkedinlist`, `checkedoutlist` (stripping the `<UUID>=` prefix), cached file path, and `lastmodtime`. Does not reconstruct media streams from `CachedMedia-*` block tables.

## Paths & Acquisition Coverage

- **iOS Full File System (FFS)**:
  - App containers: `/private/var/mobile/Containers/Data/Application/<GUID>/` (resolved to bundle ID via `.com.apple.mobile_container_manager.metadata.plist`)
  - In-app `SFSafariViewController` stores: `<AppContainer>/SystemData/com.apple.SafariViewService/Library/WebKit/WebsiteData/...` (attributed as `<bundleID> (SafariViewService)`)
  - Non-containerized daemons: `/private/var/mobile/Library/WebKit/<bundleID>/...` (e.g., `com.apple.email.maild`)
- **iOS Backups (`Manifest.db`)**:
  - Apple excludes `NetworkCache` and `WebKitCache` from standard backups (`NSURLIsExcludedFromBackupKey`). When scanning a backup, `wkparse` flags this explicitly in `coverage_gaps` and parses surviving stores. Files are staged to a temporary directory by `Manifest.db` domain (including `AppDomainGroup-` and `AppDomainPlugin-` owners) with mtimes preserved; reported paths are rewritten to `backup:<domain>/<relativePath>` and listed in `backup_files` with their file IDs. Surviving stores include `observations.db`, `WebsiteData` origins, `LocalStorage`, `ServiceWorkers`, `HSTS.plist` and `MediaCache`.
- **macOS**:
  - Sandboxed containers (`~/Library/Containers/<bundleID>/Data/...`) and non-sandboxed `~/Library/WebKit/<bundleID>/` and `~/Library/Caches/<bundleID>/` paths.
