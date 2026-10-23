#!/usr/bin/env python3
"""Checks whether any file referenced in a php-malware-finder whitelist
(entries like `hash.sha1(0, filesize) == "<hash>" // <path>`) has changed
content since it was whitelisted - meaning it will start getting
(re-)flagged on the next scan. Run this proactively (e.g. right after a
deploy/composer update) instead of waiting to notice it as fresh scan
noise days later.

Does not modify anything - just reports. Re-whitelisting a genuinely
clean change is a deliberate, reviewed step (see pmf_scan.py's own
"whitelist" mode), not something this script should do on its own.
"""
import sys
import re
import hashlib

ENTRY_RE = re.compile(r'hash\.sha1\(0,\s*filesize\)\s*==\s*"([0-9a-f]{40})".*?//\s*(\S+)')
RULE_START_RE = re.compile(r'\brule\s+(\w+)')


def check(whitelist_path):
    """Only checks hash entries inside a rule literally named Custom - the
    one pmf_scan.py's own "whitelist" mode writes to. php-malware-finder's
    other built-in whitelist rules (Magento, Roundcube, ...) hash-list
    files from generic third-party apps that may not even be installed
    here, with paths relative to wherever a site happens to use them -
    not something this host can meaningfully check for drift."""
    with open(whitelist_path) as f:
        lines = f.readlines()
    changed, missing, checked = [], [], 0
    in_custom_rule = False
    for line in lines:
        m = RULE_START_RE.search(line)
        if m:
            in_custom_rule = (m.group(1) == "Custom")
            continue
        if line.strip() == "}":
            in_custom_rule = False
            continue
        if not in_custom_rule:
            continue
        m = ENTRY_RE.search(line)
        if not m:
            continue
        expected_hash, fpath = m.group(1), m.group(2)
        checked += 1
        try:
            with open(fpath, "rb") as fh:
                actual_hash = hashlib.sha1(fh.read()).hexdigest()
        except OSError:
            missing.append(fpath)
            continue
        if actual_hash != expected_hash:
            changed.append(fpath)
    return checked, changed, missing


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <whitelist.yar>", file=sys.stderr)
        sys.exit(1)
    checked, changed, missing = check(sys.argv[1])
    print(f"# Checked {checked} whitelisted file(s): {len(changed)} changed, {len(missing)} missing")
    for p in changed:
        print(f"CHANGED\t{p}")
    for p in missing:
        print(f"MISSING\t{p}")
    sys.exit(1 if (changed or missing) else 0)


if __name__ == "__main__":
    main()
