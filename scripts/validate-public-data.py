#!/usr/bin/env python3
"""Reproduce the documented iLEAPP results using pinned, hash-checked fixtures."""

import argparse
import collections
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request
import zipfile

REVISION = "3b8b53b88a15afc7498695c256f5bb871d34e7ea"
BASE = f"https://raw.githubusercontent.com/abrignoni/iLEAPP/{REVISION}/admin/test/cases/data/"
FIXTURES = [
    ("webkitAdditionalCache/testdata.webkitAdditionalCache.webkit_additional_cache_records.case1.zip",
     "811a3c230790131fee232a614494e89d6a60c524d4b15c3b5c15f49097ff7e19"),
    ("webkitResourceLoadStatistics/testdata.webkitResourceLoadStatistics.webkit_observed_domains.case1.zip",
     "d8fa9590916040e3ed4e82a83cc8bfa084c1330a70927bc438ec6805c7b35d7b"),
    ("webkitMediaCache/testdata.webkitMediaCache.webkit_media_cache.casepublic_ios16.zip",
     "d46e9f23f6b52c201d6114b54a4f142509a2c7d750c4dcf6389c0ab5554d46f7"),
]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="built wkparse binary")
    parser.add_argument("--archives", type=Path, help="directory of previously downloaded ZIPs; disables network")
    args = parser.parse_args()
    binary = str(args.binary.resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix="wkparse-validation-") as temporary:
        root = Path(temporary).resolve()
        reports = []
        for index, (name, digest) in enumerate(FIXTURES):
            if args.archives:
                data = (args.archives / Path(name).name).read_bytes()
            else:
                with urllib.request.urlopen(BASE + name, timeout=60) as response:
                    data = response.read()
            require(hashlib.sha256(data).hexdigest() == digest, f"fixture digest mismatch: {name}")
            archive = root / f"{index}.zip"
            archive.write_bytes(data)
            evidence = root / f"evidence-{index}"
            evidence.mkdir()
            with zipfile.ZipFile(archive) as z:
                for member in z.infolist():
                    require((evidence / member.filename).resolve().is_relative_to(evidence),
                            f"unsafe archive path: {member.filename}")
                z.extractall(evidence)
            before = {p: hashlib.sha256(p.read_bytes()).digest() for p in evidence.rglob("*") if p.is_file()}
            result = subprocess.run([binary, "scan", "-format", "json", str(evidence)],
                                    check=True, capture_output=True, text=True)
            report = json.loads(result.stdout)
            reports.append(report)
            for fmt in ("summary", "timeline", "csv", "graph"):
                subprocess.run([binary, "scan", "-format", fmt, str(evidence)],
                               check=True, stdout=subprocess.DEVNULL)
            if index == 0:
                records = [r for c in report["containers"] for s in c.get("network_caches", []) for r in s["records"]]
                require(len(records) == 22, "expected 22 NetworkCache records")
                for key in ("meta_checksum_valid", "header_hash_valid", "header_checksum_valid"):
                    require(all(r.get(key) is True for r in records), f"failed {key}")
                require(sum("body" in r for r in records) == 6, "expected six inline bodies")
                require(collections.Counter(a["code"] for a in report.get("anomalies", [])) == {"missing_blob": 16},
                        "unexpected NetworkCache anomalies")
                subprocess.run([binary, "parse-record", records[0]["path"]], check=True, stdout=subprocess.DEVNULL)
                exports = root / "bodies"
                result = subprocess.run([binary, "scan", "-format", "json", "-match", "requestAnimationFrame",
                                         "-export-bodies", str(exports), "-export-matches-only", str(evidence)],
                                        check=True, capture_output=True, text=True)
                require(json.loads(result.stdout)["summary"]["body_matches"] == 1, "expected one matching body")
                body = exports / "f30671992092307cc06e8f7cdf289d765ccef4230fa5c259d58804ad31992bf0.js.bin"
                require(body.stat().st_size == 6823, "unexpected exported body")
                require(hashlib.sha256(body.read_bytes()).hexdigest() == body.name.split(".")[0], "export digest mismatch")
            after = {p: hashlib.sha256(p.read_bytes()).digest() for p in evidence.rglob("*") if p.is_file()}
            require(before == after, "scan changed evidence contents or file inventory")
        itp, media = reports[1:]
        require(itp["summary"]["observed_domains"] == 145, "expected 145 domains")
        require(itp["summary"]["itp_relationships"] == 306, "expected 306 relationships")
        require(itp["summary"]["context_signals"] == 97, "expected 97 context signals")
        require(itp["summary"]["containers"] == 14, "expected 14 ITP containers")
        require(not itp.get("anomalies"), "unexpected ITP anomalies")
        require(any("observations.db-wal" in gap for gap in itp.get("coverage_gaps", [])), "missing orphan WAL coverage gap")
        require(media["summary"]["media_cache_entries"] == 10, "expected ten media entries")
        require(not media.get("anomalies"), "unexpected MediaCache anomalies")
    print("PASS: pinned public fixtures, checksums, exports, CLI formats, and evidence preservation")


if __name__ == "__main__":
    main()
