# wkparse

`wkparse` is a standalone Go CLI and library for forensic analysis of Apple WebKit caches and storage across iOS and macOS extractions.

WebKit persists HTTP caches, Service Worker caches, and origin metadata in its binary `WTF::Persistence` format rather than SQLite or plists. `wkparse` decodes those stores alongside WebKit's SQLite and plist databases, verifies built-in SHA-1 integrity checksums, attributes artifacts to their owning app or daemon, and correlates everything into a single timeline and relationship graph.

## Supported Artifacts

| Artifact | Path / Store | Extracted Data |
| :--- | :--- | :--- |
| **NetworkCache** (v16–v18) | `NetworkCache/Version <N>/` (`Records/`, `Blobs/`, `salt`) | URLs, HTTP headers, status, redirect chains, `Vary` headers, TLS X.509 cert chains (`SecTrustSerialize`), `SubResources` page-to-asset links, decoded bodies (`gzip`/`deflate`/`br`), and unreferenced `Blobs/` |
| **CacheStorage** (v16–v19) | `CacheStorage/Version <N>/` | Service Worker `DOMCache` records, cache IDs and names (`cacheslist`), insertion timestamps, request/response headers, credentials flags, and bodies |
| **Origin Sidecars** | `WebsiteData/Default/*/origin` | `ClientOrigin` (`TopOrigin` vs `ClientOrigin`) binary sidecars, flagging cross-origin embedded storage |
| **ITP Observations** | `observations.db` (WAL-aware snapshot) | `ObservedDomains`, `OperatingDates`, all 10 domain relationship tables, and context signals for third-party embeds without recorded user interaction |
| **Web Storage & Workers** | `localstorage.sqlite3`, `*.localstorage`, `ServiceWorkerRegistrations-*.sqlite3` | LocalStorage key-value pairs with origin attribution (UTF-16LE blob decoding) and Service Worker scopes, script URLs, and update timestamps |
| **HSTS & MediaCache** | `HSTS.plist`, `MediaCache/diskcacherepository.plist` | Per-session HSTS policies/expiries and cached media URLs (`checked_in` / `checked_out`) |

## Install

Requires Go 1.26+ (use Go 1.26.11 or later for current security fixes). No C compiler is needed to build; race tests require cgo.

```bash
go install github.com/0x4d31/wkparse/cmd/wkparse@latest
```

Or build from source:

```bash
CGO_ENABLED=0 go build -trimpath -o wkparse ./cmd/wkparse
```

## Quick Start

Scan an iOS full file system (FFS) extraction, an unencrypted iOS backup (`Manifest.db`), a macOS `~/Library` snapshot, or any directory of WebKit artifacts:

```bash
# Compact triage summary
wkparse scan /path/to/extraction

# Full JSON report (retains anomalies, coverage gaps, and provenance)
wkparse scan -format json -out report.json /path/to/extraction

# Chronological UTC timeline (JSONL or CSV)
wkparse scan -format timeline /path/to/extraction > timeline.jsonl
wkparse scan -format csv -out timeline.csv /path/to/extraction

# Directed domain / redirect / subresource / cross-origin / worker graph (JSONL)
wkparse scan -format graph /path/to/extraction > graph.jsonl

# Hunt regex patterns in decoded bodies and unreferenced blobs; export only matches
wkparse scan -match 'WebAssembly|SharedArrayBuffer|eval\(' -export-bodies ./bodies -export-matches-only /path/to/extraction
```

Inspect individual binary records directly:

```bash
wkparse parse-record "/path/to/NetworkCache/Version 16/Records/.../Resource/<40-hex>"
wkparse parse-origin "/path/to/WebsiteData/Default/<hash>/origin"
```

Flags must precede the target path. See [CLI Reference, Library Usage, and Safety](docs/usage.md) for all flags, exit codes, automation checks, Go library usage, and safety limits.

## Validation Status

| Artifact | Real-Data Validation | Notes |
| :--- | :--- | :--- |
| NetworkCache v16 (iOS 16) | 22/22 records pass metadata, salted header, and `ResourceResponse` checksums ([iLEAPP test data](https://github.com/abrignoni/iLEAPP/tree/main/admin/test/cases/data)) | Archive omits `-blob` files; 16 `missing_blob` anomalies expected |
| ITP `observations.db` (iOS 16) | 145 domains and 306 relationships across 14 stores match iLEAPP | Reports 1 orphan `observations.db-wal` coverage gap |
| MediaCache (iOS 16) | 10 entries | Parses repository plist metadata only |
| NetworkCache v17/v18, `SubResources` | Synthetic fixtures only | Implemented from WebKit source; samples welcome |
| CacheStorage, origins, LocalStorage, Service Workers, HSTS | Synthetic fixtures only | Implemented from WebKit source; samples welcome |

Sanitized iOS 17/18 or macOS 14/15 samples (or individual failing records) are welcome via GitHub issues.

## Key Forensic Notes

- **Evidence preservation:** Source files are opened read-only without following symlinks; SQLite stores are copied alongside `-wal`/`-shm` into a private temporary directory before opening. Output files (`-out`) and body exports (`-export-bodies`) must live outside the evidence directory.
- **Signals vs. anomalies:** `anomalies` report parser or integrity issues (checksum mismatches, missing blobs, truncated data, parse errors). `signals` flag common benign patterns (such as third-party embeds without recorded ITP user interaction) for pivoting, not as standalone findings. `coverage_gaps` surface unreadable stores and iOS backup exclusions.
- **Unreferenced blobs:** Files in `Blobs/` without a surviving record occur routinely during cache eviction and are not proof of deletion by themselves.

## Documentation

- [CLI Reference, Library Usage, and Safety](docs/usage.md) — Flags, exit codes, automation, Go library API, safety limits, and reproducible validation
- [Real-World Examples](docs/examples.md) — Walkthroughs and outputs from public iOS 16 WebKit extractions, plus hunting pivots
- [Format & Path Reference](docs/formats.md) — `WTF::Persistence` wire layout, NetworkCache v16–v18 sub-variants, iOS/macOS paths, and backup coverage gaps

## Prior Art

[iLEAPP](https://github.com/abrignoni/iLEAPP) includes WebKit modules (`webkitAdditionalCache`, `webkitMediaCache`, `webkitResourceLoadStatistics`, contributed by Forensik.IT), reconstructs playable `CachedMedia-*` files, and is tested across multi-version iOS corpora. Its public iOS 16 test archives are used for `wkparse`'s real-data validation. `wkparse` complements full-device suites as a single-binary CLI and Go library focused on full `WTF::Persistence` decoding, checksum verification, TLS cert chains, decompressed body hunting, CacheStorage, origin sidecars, macOS stores, and cross-store correlation.

## License

MIT. See [LICENSE](LICENSE). Include [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) when redistributing binaries. Security issues: see [SECURITY.md](SECURITY.md).
