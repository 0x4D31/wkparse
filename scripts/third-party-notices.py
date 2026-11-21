#!/usr/bin/env python3
"""Collect dependency license texts for source/binary redistribution. Run from repo root."""

import json
import os
from pathlib import Path
import subprocess


def main():
    go = os.environ.get("GO", "go")
    manifest = json.loads(subprocess.check_output([go, "mod", "edit", "-json"], text=True))
    names = [m["Path"] for m in manifest["Require"]]
    raw = subprocess.check_output([go, "list", "-m", "-json", *names], text=True)
    decoder = json.JSONDecoder()
    modules = []
    while raw.strip():
        module, end = decoder.raw_decode(raw.lstrip())
        raw = raw.lstrip()[end:]
        if not module.get("Main"):
            modules.append(module)
    sections = [
        "# Third-party notices\n\n"
        "wkparse itself is MIT licensed; see LICENSE. Dependencies retain their own licenses.\n"
        "Include this file and LICENSE when redistributing binaries. Regenerate after dependency\n"
        "updates with `python3 scripts/third-party-notices.py` (after `go mod download`).\n"
        "The upstream modernc notices also describe bundled C code and components outside\n"
        "the runtime build; they are retained in full. This is a conservative notice bundle,\n"
        "not a claim that every component below is linked into every platform's executable.\n"
    ]
    goroot = Path(subprocess.check_output([go, "env", "GOROOT"], text=True).strip())
    sections.append("## Go runtime and standard library\n\n" + (goroot / "LICENSE").read_text())
    for module in sorted(modules, key=lambda m: m["Path"]):
        directory = Path(module["Dir"])
        licenses = sorted(p for p in directory.glob("LICENSE*") if p.is_file())
        licenses += sorted(p for p in directory.glob("COPYING*") if p.is_file())
        # Brotli carries a separate notice for its flate implementation.
        if module["Path"] == "github.com/andybalholm/brotli":
            licenses.append(directory / "flate" / "LICENSE")
        if not licenses:
            raise RuntimeError(f"No license text found for {module['Path']}")
        sections.append(f"## {module['Path']} {module['Version']}\n")
        for path in licenses:
            sections.append(f"### {path.relative_to(directory)}\n\n" + path.read_text())
    text = "\n\n".join(sections)
    Path("THIRD_PARTY_NOTICES.md").write_text("\n".join(line.rstrip() for line in text.splitlines()).rstrip() + "\n")


if __name__ == "__main__":
    main()
