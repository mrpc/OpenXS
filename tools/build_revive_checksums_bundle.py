#!/usr/bin/env python3
"""Maintainer-only tool - NOT run on customer servers. Downloads every
tagged Revive Adserver release from GitHub (no uploaded release assets
exist - confirmed via the releases API, which returns none; only tags),
hashes every file inside, and writes tools/revive_checksums/<version>.json.gz,
one file per version, committed to the repo. A released version's files
never change, so re-running this later only ever ADDS new files for
newly tagged versions - existing ones are left alone.
"""
import json
import os
import re
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import revive_core_checksums as rcc

TAGS_URL = "https://api.github.com/repos/revive-adserver/revive-adserver/tags?per_page=100"
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "revive_checksums")


def list_versions():
    versions = set()
    page = 1
    while True:
        url = f"{TAGS_URL}&page={page}"
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read())
        if not data:
            break
        for tag in data:
            name = tag.get("name", "")
            if re.match(r"^v?\d+\.\d+\.\d+$", name):
                versions.add(name.lstrip("v"))
        page += 1
    return sorted(versions)


def fetch_and_save(version):
    out_path = os.path.join(OUT_DIR, f"{version}.json.gz")
    if os.path.exists(out_path):
        return "skipped (already bundled)"
    checksums = rcc.compute_checksums_from_tarball(version)
    if not checksums:
        return "FAILED (download or extraction failed)"
    import gzip
    with gzip.open(out_path, "wt") as f:
        json.dump(checksums, f)
    return f"ok ({len(checksums)} files)"


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    versions = list_versions()
    print(f"# {len(versions)} Revive Adserver versions to check")
    for i, v in enumerate(versions, 1):
        result = fetch_and_save(v)
        print(f"[{i}/{len(versions)}] {v}: {result}")
        if "FAILED" not in result and "skipped" not in result:
            time.sleep(0.5)  # be polite to GitHub


if __name__ == "__main__":
    main()
