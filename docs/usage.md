# CLI Reference, Library Usage, and Safety

## CLI Reference

### `wkparse scan [flags] <path>`

Scans an iOS full file system (FFS) extraction, an unencrypted iOS backup (`Manifest.db`), a macOS `~/Library` snapshot, or any directory containing WebKit artifacts.

- `-format <fmt>`: `summary` (default) | `json` | `timeline` | `csv` | `graph`
- `-out <file>`: write output to a new file outside the evidence directory; existing files are never overwritten
- `-export-bodies <dir>`: export decoded bodies and unreferenced blobs as `<sha256>.<type>.bin` (or `<sha256>.bin` for unknown types; `<sha256>.partial.<type>.bin` when the decompression cap is hit). Exported files use mode `0600` inside a `0700` directory when created by `wkparse`
- `-match <regex>`: Go regular expression applied to decompressed bodies and unreferenced blobs (up to 10 deduplicated matches per body; no lookbehind or backreferences)
- `-export-matches-only`: requires `-match` and `-export-bodies`; exports only matching payloads
- `-max-decompress-mib <n>`: per-body decompressed size cap in MiB (default `32`); truncation is flagged as `decompression_cap_reached`
- `-verbose`: list all containers, anomalies, and context signals in `summary` output (default caps containers at 15 and each anomaly/signal code at 10)

### `wkparse parse-record [flags] <file>`

Decodes a single binary `NetworkCache` or `CacheStorage` record and prints JSON to stdout.

- `-kind <kind>`: `auto` (default) | `netcache` | `cachestorage`
- `-salt <file>`: path to an 8-byte store `salt` file (auto-discovered from enclosing `Version <N>/salt` or `CacheStorage/salt` when omitted)
- `-export-bodies`, `-match`, `-max-decompress-mib`: same as `scan`

When `-kind auto` is used, paths containing `/CacheStorage/` are decoded as `CacheStorage`; all other paths default to `NetworkCache`. For a detached or renamed record, pass `-kind` explicitly. When no salt is found, salted hash verification fields are omitted rather than reported as passing.

### `wkparse parse-origin <file>`

Decodes a single WebKit Unified Origin Storage `origin` sidecar and prints JSON to stdout.

### `wkparse version`

Prints the `wkparse` version.

## Flag Parsing, Exit Codes, and Automation

- **Flag ordering:** Flags must precede the target path (Go's standard `flag` package). Both `-flag` and `--flag` are accepted; use `--` before a path starting with a dash, and quote paths containing spaces (for example `wkparse scan "/cases/iPhone extraction"`).
- **Exit codes:** `0` = command completed (or displayed help), `1` = I/O or fatal parsing error, `2` = invalid arguments.
- **Checking completeness:** A scan that exits `0` can still contain anomalies or coverage gaps, and `timeline`, `csv`, and `graph` outputs contain events or edges only. Save a JSON report to retain anomalies, coverage gaps, and provenance, and check them explicitly:

```bash
wkparse scan -format json -out report.json /path/to/extraction
jq -e '(.anomalies // [] | length) == 0 and (.coverage_gaps // [] | length) == 0' report.json
```

This check intentionally treats expected missing blobs and other coverage gaps as requiring review. An empty successful scan does not prove an extraction has no WebKit activity.

## Interpreting Output

- **Anomalies** are parser or integrity findings: checksum mismatches, truncated or trailing data, missing blobs, body size mismatches, unsupported versions, read errors, and parse errors. A parse error in one artifact is reported and the scan continues.
- **Context signals** are common on benign data (such as a third-party embed in ITP with no recorded first-party user interaction). Use them as pivots, not findings.
- **Coverage gaps** list evidence `wkparse` saw but could not parse (for example, an `observations.db-wal` with no main database) as well as standard iOS backup exclusions.
- **Unreferenced blobs** are `Blobs/` files no surviving record points to. Normal cache eviction produces them; they are not evidence of deletion on their own. If any record in the same store failed to parse, an `unreferenced_blob_caveat` is added because those records' references are unknown.
- **Timestamps** come from WebKit's own fields where available. Unreferenced-blob events fall back to filesystem mtime (`time_source: fs_mtime`), which depends on how the extraction preserved metadata.
- **iOS backups** report paths as `backup:<domain>/<relativePath>`, and `backup_files` maps them back to `Manifest.db` file IDs.

## Go Library

```go
package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/0x4d31/wkparse/pkg/scanner"
)

func main() {
	report, err := scanner.Scan("/path/to/extraction", scanner.Options{})
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		log.Fatal(err)
	}
	// Inspect report.Anomalies and report.CoverageGaps even when err == nil.
}
```

Package layout:

- `pkg/scanner`: discovery, owner attribution, correlation, timeline, and graph builder
- `pkg/webkit`: `NetworkCache`, `CacheStorage`, `origin`, and body analysis/export
- `pkg/stores`: SQLite (`observations.db`, LocalStorage, Service Workers) and plist (`HSTS.plist`, `MediaCache`) readers
- `pkg/persist`: `WTF::Persistence` binary codec and typed SHA-1 checksum verification

When calling low-level body export APIs directly, choose an output directory outside all evidence (`scanner.Scan` and `parse-record` enforce this for their targets). The Go API and JSON schema may evolve before `v1.0`.

## Safety and Limits

- **Read-only evidence handling:** Source files are opened read-only and never modified. Directory walks do not follow symlinks, and file readers reject symlink leaves. SQLite databases are copied alongside `-wal` and `-shm` into a private temporary directory before opening so WAL recovery occurs only on the copy.
- **Fault containment:** Parsers are bounds-checked and fuzzed; an unexpected panic in one artifact is recovered and reported as `parser_panic`.
- **Operational guidance:** Scan a stationary, read-only extraction rather than a live SQLite database, and run as a nonprivileged user. The decompression cap applies per body; raw inputs, regex matches, and large reports can still consume substantial memory, so apply process memory and disk limits on untrusted inputs.
- **Output isolation:** Keep `-out` and `-export-bodies` outside the evidence directory. Use a private export directory on a filesystem that supports hard links. A reused export file is accepted only if its contents match the expected digest; conflicts and failed writes produce `export_error`. On Windows, restrict the output directory's ACL because POSIX modes do not enforce access control there.

## Development and Reproducible Validation

```bash
go test -race ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
CGO_ENABLED=0 go build -trimpath -o wkparse ./cmd/wkparse
python3 scripts/validate-public-data.py ./wkparse
```

`scripts/validate-public-data.py` (Python 3.9+) downloads three public iLEAPP archives from a pinned commit, verifies their SHA-256 hashes, and checks the documented counts, checksums, body export, and evidence immutability inside a temporary directory. Pass `--archives /path/to/zips` for offline validation. CI also runs fuzz smoke tests and cross-builds for macOS, Linux, and Windows.
