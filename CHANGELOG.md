# Changelog

## v0.1.0

Initial release.

- NetworkCache v16–v18 record decoding with metadata, salted header/body, and `ResourceResponse` checksum verification, TLS certificate chains, `SubResources` (rejecting trailing header bytes), inline and external bodies (with size-mismatch detection even without salt), and unreferenced blobs
- CacheStorage v16–v19 records with `cache_id`, `cacheslist` names, and parent/version `salt` discovery (current and legacy layouts)
- WebsiteData `origin` sidecars, ITP `observations.db`, LocalStorage (with UTF-16LE blob decoding and origin attribution), Service Worker registrations (resolving stored scope paths and `topOrigin` database identifiers while preserving raw fields), per-session HSTS policies, and MediaCache
- iOS FFS, iOS backup (`Manifest.db` + WAL), and macOS directory scanning with owner attribution, `backup:<domain>/<path>` provenance, and per-artifact error containment
- Correlated timeline, directed graph (including same-origin and cross-origin Service Worker registrations), anomalies, context signals, and coverage gaps
- Evidence-safe file handling: read-only evidence opens, symlink rejection, `-out` non-overwrite outside evidence, single-record export boundary checks, bounded decompression (`-max-decompress-mib`), verified `.bin` exports (`0600`), and `-export-matches-only`
- Panic containment per artifact, fuzz targets for record, origin, and body parsers, pinned public-data validation tooling, and third-party license notices
- Validated against iLEAPP's public iOS 16 test data (NetworkCache v16, ITP `observations.db`, MediaCache)
