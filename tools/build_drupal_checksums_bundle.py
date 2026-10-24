#!/usr/bin/env python3
"""Maintainer-only tool - NOT run on customer servers. Downloads every
released Drupal 7.x tarball from drupal.org, hashes every file inside,
and writes tools/drupal_checksums/<version>.json.gz, one file per
version, committed to the repo. A released version's files never
change, so re-running this later only ever ADDS new files for newly
released Drupal 7.x point releases (there's still occasional security
releases despite the branch itself being unsupported) - existing ones
are left alone, keeping git history clean.

Drupal 7.x only, ~99 releases as of 2026-10-24 - this is the only
major version actually found installed across our fleet so far (8+
uses a completely different, Composer-managed layout). Heavier than
the WordPress bundle (a real tarball download+extract per version,
not a single lightweight API call) since drupal.org has no per-file
checksums API - expect this to take a while the first time; re-runs
are fast (skips anything already bundled).
"""
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drupal_core_checksums as dcc

RELEASE_HISTORY_URL = "https://updates.drupal.org/release-history/drupal/7.x"
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "drupal_checksums")


def list_versions():
    with urllib.request.urlopen(RELEASE_HISTORY_URL, timeout=15) as resp:
        xml = resp.read().decode("utf-8", errors="replace")
    import re
    return sorted(set(re.findall(r"<version>(7\.\d+)</version>", xml)),
                  key=lambda v: int(v.split(".")[1]))


def fetch_and_save(version):
    out_path = os.path.join(OUT_DIR, f"{version}.json.gz")
    if os.path.exists(out_path):
        return "skipped (already bundled)"
    checksums = dcc.compute_checksums_from_tarball(version)
    if not checksums:
        return "FAILED (download or extraction failed)"
    import gzip
    with gzip.open(out_path, "wt") as f:
        json.dump(checksums, f)
    return f"ok ({len(checksums)} files)"


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    versions = list_versions()
    print(f"# {len(versions)} Drupal 7.x versions to check")
    for i, v in enumerate(versions, 1):
        result = fetch_and_save(v)
        print(f"[{i}/{len(versions)}] {v}: {result}")
        if "FAILED" not in result and "skipped" not in result:
            time.sleep(0.5)  # be polite to drupal.org/ftp.drupal.org


if __name__ == "__main__":
    main()
