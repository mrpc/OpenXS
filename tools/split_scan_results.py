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
forever. A missing new_findings_path disables this filtering (everything
counts as "new"); an existing but empty one means nothing is new.

serious lines that are also new are additionally written to
<out_prefix>.serious_new.txt and counted as new_serious, so the e-mail can
put a freshly compromised site on top instead of burying it among the
same unresolved hits it lists every night.

Usage: split_scan_results.py <scan_results.txt> <new_findings.txt> <out_prefix>
Writes <out_prefix>.serious.txt / .heuristic.txt / .fs.txt (only the
non-empty ones) and prints "serious=N heuristic=N fs=N new_serious=N" for
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

    # Only a MISSING file means "don't filter": pmf_scan.py always writes it,
    # so an empty one is a night with no new findings - treating that as
    # "no filter" used to report every old heuristic hit as NEW.
    has_new = bool(new_findings_path) and os.path.isfile(new_findings_path)
    is_new = set(_read_lines(new_findings_path)) if has_new else None

    buckets = {"serious": [], "heuristic": [], "fs": [], "serious_new": []}
    for line in _read_lines(results_path):
        _, rule = line.split("\t", 1)
        category = pmf_scan.categorize(rule)
        tier = "serious" if category in SERIOUS else ("fs" if category == "fs" else "heuristic")
        if tier != "serious" and is_new is not None and line not in is_new:
            continue
        buckets[tier].append(line)
        if tier == "serious" and (is_new is None or line in is_new):
            buckets["serious_new"].append(line)

    for tier, lines in buckets.items():
        if lines:
            with open(f"{out_prefix}.{tier}.txt", "w") as f:
                f.write("\n".join(lines) + "\n")

    counts = {tier: len(lines) for tier, lines in buckets.items()}
    counts["new_serious"] = counts.pop("serious_new")
    print(" ".join(f"{k}={v}" for k, v in counts.items()))


if __name__ == "__main__":
    main()
