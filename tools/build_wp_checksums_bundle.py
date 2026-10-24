#!/usr/bin/env python3
"""Maintainer-only tool - NOT run on customer servers. Fetches official
WordPress core checksums for every released version >= 5.0 (Dec 2018
onward - realistically covers any site still in production use) from
wordpress.org and writes them as tools/wp_checksums/<version>.json.gz,
one file per version, committed to the repo. A released version's
checksums never change, so re-running this later only ever ADDS new
files for newly-released WP versions - existing ones are left alone,
keeping git history clean.

Run this, commit the new files under tools/wp_checksums/, done. The
runtime side (wp_core_checksums.py) reads from this bundle first and
only falls back to a live API call for a version it doesn't find here
(e.g. one released after the bundle was last updated).
"""
import gzip
import json
import os
import re
import sys
import time
import urllib.request

STABLE_CHECK_URL = "https://api.wordpress.org/core/stable-check/1.0/"
CHECKSUMS_URL = "https://api.wordpress.org/core/checksums/1.0/?version={version}&locale=en_US"
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wp_checksums")
MIN_VERSION = (5, 0, 0)


def _vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v.split("-")[0])[:3])


def list_versions():
    with urllib.request.urlopen(STABLE_CHECK_URL, timeout=10) as resp:
        data = json.loads(resp.read())
    return sorted((v for v in data if _vtuple(v) >= MIN_VERSION), key=_vtuple)


def fetch_and_save(version):
    out_path = os.path.join(OUT_DIR, f"{version}.json.gz")
    if os.path.exists(out_path):
        return "skipped (already bundled)"
    url = CHECKSUMS_URL.format(version=version)
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        return f"FAILED: {e}"
    checksums = data.get("checksums")
    if not checksums:
        return "no checksums in response (skipped)"
    with gzip.open(out_path, "wt") as f:
        json.dump(checksums, f)
    return f"ok ({len(checksums)} files)"


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    versions = list_versions()
    print(f"# {len(versions)} versions >= {'.'.join(map(str, MIN_VERSION))} to check")
    for i, v in enumerate(versions, 1):
        result = fetch_and_save(v)
        print(f"[{i}/{len(versions)}] {v}: {result}")
        if "FAILED" not in result and "skipped" not in result:
            time.sleep(0.3)  # be polite to wordpress.org's API


if __name__ == "__main__":
    main()
