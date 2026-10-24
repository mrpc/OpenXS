#!/usr/bin/env python3
"""Maintainer-only tool - NOT run on customer servers. Downloads every
tagged phpMyAdmin release's "all-languages" zip from files.phpmyadmin.net,
hashes every file inside, and writes
tools/phpmyadmin_checksums/<version>.json.gz, one file per version,
committed to the repo. A released version's files never change, so
re-running this later only ever ADDS new files for newly tagged
versions - existing ones are left alone.
"""
import json
import os
import re
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import phpmyadmin_core_checksums as pcc

# phpMyAdmin's GitHub tags are "RELEASE_X_Y_Z" (sometimes with an "RC1"-
# style suffix, excluded here - we only want actual releases, matching
# what files.phpmyadmin.net's version directories use, "X.Y.Z").
TAGS_URL = "https://api.github.com/repos/phpmyadmin/phpmyadmin/tags?per_page=100"
TAG_RE = re.compile(r"^RELEASE_(\d+)_(\d+)_(\d+)$")
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phpmyadmin_checksums")


def list_versions(min_version=None):
    versions = set()
    page = 1
    while True:
        url = f"{TAGS_URL}&page={page}"
        req = urllib.request.Request(url, headers={"User-Agent": "openxs-checksum-bundler"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        if not data:
            break
        for tag in data:
            m = TAG_RE.match(tag.get("name", ""))
            if not m:
                continue
            parts = tuple(int(x) for x in m.groups())
            if min_version is None or parts >= min_version:
                versions.add(".".join(m.groups()))
        page += 1
    return sorted(versions, key=lambda v: tuple(map(int, v.split("."))))


def fetch_and_save(version):
    out_path = os.path.join(OUT_DIR, f"{version}.json.gz")
    if os.path.exists(out_path):
        return "skipped (already bundled)"
    checksums = pcc.compute_checksums_from_zip(version)
    if not checksums:
        return "FAILED (download or extraction failed)"
    import gzip
    with gzip.open(out_path, "wt") as f:
        json.dump(checksums, f)
    return f"ok ({len(checksums)} files)"


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    # min_version arg lets the initial seed stay small (our own fleet's
    # oldest install + recent releases) instead of every version back
    # to the project's start - pass none for a full historical bundle.
    min_version = tuple(map(int, sys.argv[1].split("."))) if len(sys.argv) > 1 else None
    versions = list_versions(min_version)
    print(f"# {len(versions)} phpMyAdmin versions to check")
    for i, v in enumerate(versions, 1):
        result = fetch_and_save(v)
        print(f"[{i}/{len(versions)}] {v}: {result}")
        if "FAILED" not in result and "skipped" not in result:
            time.sleep(0.5)  # be polite to the server


if __name__ == "__main__":
    main()
