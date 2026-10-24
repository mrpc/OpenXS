#!/usr/bin/env python3
"""Splits pmf_scan.py's raw scan_results.txt (one 'path\\trule' line per
finding, every category mixed together) into one file per severity tier,
so the scheduled-scan email and anything else consuming this output can
lead with what actually needs a human's attention instead of a wall of
mostly-noise generic heuristic hits.

Tiers:
  serious   - virus/yara_exploit/maldet (pmf_scan.categorize()'s own
              auto-quarantine-eligible categories) - always included in
              full, every scan, whether or not it's been seen before:
              an unresolved real backdoor should keep nagging until
              it's actually quarantined, not go quiet just because it's
              been seen once already.
  heuristic - yara_heuristic (generic ObfuscatedPhp/DodgyPhp/etc., and
              the vendored webshell ruleset - known to recur on common,
              legitimate software; see default_ignore/RULE_PARANOIA_LEVEL)
  fs        - filesystem hygiene (symlinks, world-writable dirs, ...) -
              not a malware signal at all

heuristic/fs are filtered down to only findings present in
new_findings_path (pmf_scan.py's own openxs_db.new_finding_ids() output,
first-seen-ever findings) - an unchanged legitimate-but-obfuscated-
looking plugin file shouldn't nag on every single scheduled scan
forever. Pass an empty/missing new_findings_path to disable this
filtering (everything counts as "new").

Usage: split_scan_results.py <scan_results.txt> <new_findings.txt> <out_prefix>
Writes <out_prefix>.serious.txt / .heuristic.txt / .fs.txt (only the
non-empty ones) and prints "serious=N heuristic=N fs=N" to stdout for
the calling shell script to eval.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pmf_scan

SERIOUS = {"virus", "yara_exploit", "maldet"}


def _read_lines(path):
    if not path or not os.path.isfile(path):
        return []
    with open(path) as f:
        return [line.rstrip("\n") for line in f if line.strip() and "\t" in line]


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <scan_results.txt> <new_findings.txt> <out_prefix>", file=sys.stderr)
        sys.exit(1)
    results_path, new_findings_path, out_prefix = sys.argv[1:4]

    new_lines = _read_lines(new_findings_path)
    is_new = set(new_lines) if new_lines else None  # None = don't filter at all

    buckets = {"serious": [], "heuristic": [], "fs": []}
    for line in _read_lines(results_path):
        _, rule = line.split("\t", 1)
        category = pmf_scan.categorize(rule)
        tier = "serious" if category in SERIOUS else ("fs" if category == "fs" else "heuristic")
        if tier != "serious" and is_new is not None and line not in is_new:
            continue
        buckets[tier].append(line)

    for tier, lines in buckets.items():
        if lines:
            with open(f"{out_prefix}.{tier}.txt", "w") as f:
                f.write("\n".join(lines) + "\n")

    print(" ".join(f"{tier}={len(lines)}" for tier, lines in buckets.items()))


if __name__ == "__main__":
    main()
