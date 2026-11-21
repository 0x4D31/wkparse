# Real-World Examples

The walkthroughs below summarize actual `wkparse` runs against public iOS 16 WebKit forensic test datasets published in [abrignoni/iLEAPP](https://github.com/abrignoni/iLEAPP) (MIT license). No third-party device data is bundled in this repository; each dataset can be downloaded directly from the iLEAPP repository to reproduce these results.

To reproduce the checks automatically, build `wkparse` and run:

```bash
python3 scripts/validate-public-data.py ./wkparse
```

The script pins the upstream revision and archive hashes and checks all three datasets.
For offline runs, place the three named ZIP archives in one directory and add
`--archives /path/to/zips`. The examples below assume each archive has been extracted
into the directory named in its command. Output paths must be outside those directories.

## 1. iOS 16 `NetworkCache` v16: Headers, Bodies and TLS Certificate Chains

Dataset: `testdata.webkitAdditionalCache.webkit_additional_cache_records.case1.zip` (iOS 16 FFS slice containing 22 real `NetworkCache/Version 16` records across Duolingo and Gmail's embedded `SFSafariViewController`).

```bash
wkparse scan -format summary ./webkit_additional_cache_records.case1
```

Summarized output:

```text
Target:            .../webkit_additional_cache_records.case1
Acquisition:       ios_ffs
Containers:        2
NetworkCache:      22 records (0 subresource links, 0 unreferenced blobs)
CacheStorage:      0 records
Origins:           0 (0 cross-origin)
ITP observations:  0 domains (0 relationships)
LocalStorage/SW:   0 items / 0 workers / 0 HSTS / 0 media
Matches/Anomalies: 0 matches / 16 anomalies / 0 context signals

Containers:
  - com.duolingo.DuolingoMobile (netcache=2)
  - com.google.Gmail (SafariViewService) (netcache=20)

Anomalies (missing_blob=16):
  ...
```

Key verification results across all 22 real records:

- **22 / 22** passed `WTF::Persistence` metadata SHA-1 checksum verification.
- **22 / 22** passed salted header SHA-1 verification against the auto-discovered `Version 16/salt` file.
- **22 / 22** passed `ResourceResponse` header `WTF::Persistence` SHA-1 checksum verification (including the iOS 16.0–16.3 wire layout without `wasPrivateRelayed` and records with embedded `SecTrustSerialize` certificates).
- **6 / 6** inline bodies decoded, including `scheduler.js` (6,823 bytes). WebKit stores this body already decoded even though the response carries `Content-Encoding: br`, so `wkparse` falls back to the raw bytes and reports `decompressed: false` with identical raw and decoded SHA-256.
- No `trailing_data` anomalies: every inline body ends exactly at the end of the record file.
- The 16 `missing_blob` anomalies are expected: the test archive omits the external `-blob` files and `Blobs/` directory.

Inspecting a single record with an embedded TLS trust object (`parse-record` auto-discovers `Version 16/salt`):

```bash
wkparse parse-record \
  "./webkit_additional_cache_records.case1/private/var/mobile/Containers/Data/Application/89A6AE48-C46D-4405-A187-C7FF439873F3/Library/Caches/WebKit/NetworkCache/Version 16/Records/7178A7B2850DA60D1E9A1819E8788B552D62F687/Resource/45061F6570B0E7C59CFC7A8C7BCFEC64D48AE9F9"
```

Excerpt from JSON output (verified checksums + X.509 chain extracted from Apple's ASN.1 DER `SecTrustSerialize` blob):

```json
{
  "version": 16,
  "key": {
    "partition": "doubleclick.net",
    "type": "Resource",
    "identifier": "https://googleads.g.doubleclick.net/mads/static/sdk/native/sdk-core-v40.html?sdk=afma-sdk-i-v9.5.0"
  },
  "timestamp": "2023-01-03T12:14:28.244863033Z",
  "meta_checksum_valid": true,
  "header_hash_valid": true,
  "header_checksum_valid": true,
  "response": {
    "mime_type": "text/html",
    "http_status_code": 200,
    "http_version": "HTTP/3.0",
    "certificates": [
      {
        "subject": "CN=*.g.doubleclick.net",
        "issuer": "CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
        "not_before": "2022-11-28T08:16:14Z",
        "not_after": "2023-02-20T08:16:13Z",
        "sha256": "d1ef02bb7f6698698d8d09b478ee8e2577bf2e3d30b13a7500acbededfaa3490"
      }
    ],
    "source": "DiskCacheAfterValidation"
  }
}
```

Hunting inside decoded bodies and exporting only the matches:

```bash
wkparse scan -match 'requestAnimationFrame' -export-bodies ./bodies -export-matches-only ./webkit_additional_cache_records.case1
```

```text
Matches/Anomalies: 1 matches / 16 anomalies / 0 context signals
...
Body Matches:
  - [com.google.Gmail (SafariViewService)] https://m.youtube.com/static/r/51f14443/scheduler.vflset/scheduler.js -> [requestAnimationFrame] (sha256=f30671992092307cc06e8f7cdf289d765ccef4230fa5c259d58804ad31992bf0)
```

```text
$ ls -l ./bodies
-rw-------  1 user  user  6823  f30671992092307cc06e8f7cdf289d765ccef4230fa5c259d58804ad31992bf0.js.bin
```

Exported files are named by decoded SHA-256 with a `.bin` suffix to reduce accidental opening or execution.

Exporting the chronological UTC timeline as CSV:

```bash
wkparse scan -format csv ./webkit_additional_cache_records.case1 | head -n 4
```

```csv
timestamp_utc,time_source,owner,source,action,target,detail
2022-12-23T16:38:23.339320898Z,,com.google.Gmail (SafariViewService),network_cache,cached_Resource,https://m.youtube.com/static/r/51f14443/scheduler.vflset/scheduler.js,status=200 mime=text/javascript size=6823
2022-12-23T16:38:23.465455055Z,,com.google.Gmail (SafariViewService),network_cache,cached_Resource,https://m.youtube.com/s/_/ytmweb/_/ss/.../rs=ABnK5FKTA8hJefYWhEZ18N20S8JICJZdYA,status=200 mime=text/css size=461300
2022-12-23T16:38:23.769655942Z,,com.google.Gmail (SafariViewService),network_cache,cached_Resource,https://m.youtube.com/s/_/ytmweb/_/js/.../m=c3_base,status=200 mime=text/javascript size=910188
```

## 2. iOS 16 `observations.db` (ITP Domains & Cross-Domain Relationships)

Dataset: `testdata.webkitResourceLoadStatistics.webkit_observed_domains.case1.zip` (14 real `observations.db` files across Safari, Chrome iOS, Gmail `SafariViewService`, Mail daemon, TikTok, Duolingo, Reddit, Discord, and others).

```bash
wkparse scan -format summary ./webkit_observed_domains.case1
```

Summarized output:

```text
Acquisition:       ios_ffs
Containers:        14
ITP observations:  145 domains (306 relationships)
Matches/Anomalies: 0 matches / 0 anomalies / 97 context signals

Coverage Gaps:
  - com.google.keyboard: observations.db-wal (461472 bytes) present without observations.db; WAL contents not parsed (.../1DF3C4EC-B1DB-4B74-8B62-3A5D12CBB05C/Library/WebKit/WebsiteData/ResourceLoadStatistics/observations.db-wal)

Containers:
  - com.apple.email.maild (empty store)
  - com.apple.mobilemail (empty store)
  - com.apple.mobilesafari (itp=20/41)
  - com.duolingo.DuolingoMobile (itp=1/0)
  - com.google.Gmail (SafariViewService) (itp=7/13)
  - com.google.Vespa (itp=3/3)
  - com.google.chrome.ios (itp=94/241)
  - com.yikyak.2 (itp=9/8)
  - com.zhiliaoapp.musically (itp=11/0)
  ...

Context signals are common on benign data; review them, do not treat them as findings.

Context signals (third_party_without_user_interaction=97):
  - [third_party_without_user_interaction] com.apple.mobilesafari: google.com embedded youtube.com (subframe_under); youtube.com has no recorded first-party user interaction
  - [third_party_without_user_interaction] com.apple.mobilesafari: lufthansa.com embedded doubleclick.net (subframe_under); doubleclick.net has no recorded first-party user interaction
  ...
```

The 97 signals include familiar ad, analytics and CDN domains. A missing interaction flag does not establish what an embed did or whether it was benign.

The coverage gap shows a store `wkparse` cannot read: the extraction contains only the WAL file for `com.google.keyboard`. It is reported so the examiner knows to recover it with a WAL-aware tool.

All 145 `ObservedDomains` and all 306 relationships across 8 populated tables (`subresource_under=160`, `third_party_script=83`, `subframe_under=16`, `subresource_redirect_from=12`, `subresource_redirect_to=12`, `top_redirect_from=8`, `top_redirect_to=8`, `top_redirect_to_strict_samesite=7`) match the iLEAPP ground-truth counts exactly, with all 14 containers attributed by bundle ID.

## 3. iOS 16 `MediaCache`

Dataset: `testdata.webkitMediaCache.webkit_media_cache.casepublic_ios16.zip`.

```bash
wkparse scan -format summary ./webkit_media_cache.casepublic_ios16
```

```text
Acquisition:       ios_ffs
Containers:        2
LocalStorage/SW:   0 items / 0 workers / 0 HSTS / 10 media

Containers:
  - com.google.Gmail (SafariViewService) (media=5)
  - com.google.chrome.ios (media=5)
```

## 4. Hunting Pivots for Hidden Iframes and Staged Payloads

For browser-delivered exploitation (watering holes or hidden iframes via Safari, `SFSafariViewController` or in-app `WKWebView`), these pivots narrow review. Expect benign hits for each one; treat them as leads to corroborate with other evidence.

1. **Third-party subframes and cross-origin storage.** Embeds with no recorded user interaction are normal for ads and analytics, so start from unfamiliar domains and correlate with timeline activity:
   ```bash
   wkparse scan -format graph /path/to/ffs | jq 'select(.kind == "subframe_under" or .kind == "cross_origin_client")'
   wkparse scan -format json /path/to/ffs | jq '.signals[]?'
   ```
2. **Regex hunting in decoded JS/HTML/WASM bodies and unreferenced blobs**, exporting only matching payloads for static review:
   ```bash
   wkparse scan \
     -match 'WebAssembly\.instantiate|SharedArrayBuffer|addrof|fakeobj|mach_port' \
     -export-bodies ./recovered_bodies -export-matches-only \
     -format json -out triage.json \
     /path/to/ffs
   ```
   Large JS bundles legitimately contain `WebAssembly` and `SharedArrayBuffer`; exploit-specific terms such as `addrof` and `fakeobj` are lower-noise.
3. **Integrity and leftovers.** Checksum mismatches can come from tampering, partial writes or extraction errors. Unreferenced blobs are routinely produced by cache eviction. Neither proves anti-forensic activity on its own:
   ```bash
   jq '.anomalies[]? | select(.code == "unreferenced_blob" or (.code | endswith("_mismatch")))' triage.json
   ```
