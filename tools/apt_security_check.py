#!/usr/bin/env python3
"""Checks for pending apt security updates - a different, OS-level
question from version_scan.py's application-layer checks (WordPress,
composer packages). Portable across Debian and Ubuntu (the fleet mixes
both) via plain `apt-get -s dist-upgrade` (simulate, never installs
anything), rather than Ubuntu-only tools like update-notifier's
apt-check, which isn't available on Debian at all (verified: not present
on balrog, a Debian 12 box).

Report-only, like the other checkers here.
"""
import re
import subprocess
import sys

INST_RE = re.compile(r"^Inst (\S+) \[([^\]]+)\] \(([^ ]+) ([^)]+)\)")


def pending_updates(refresh=True, timeout=120):
    """Returns a list of (package, current_version, new_version, is_security)
    tuples. refresh=True runs `apt-get update` first (stale package lists
    would otherwise under-report what's actually pending) - fine for a
    once-daily check, not meant to be called on every file scan."""
    if refresh:
        try:
            subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=timeout)
        except Exception:
            pass  # proceed with whatever lists are already there

    try:
        out = subprocess.run(["apt-get", "-s", "dist-upgrade"],
                              capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return []

    results = []
    for line in out.splitlines():
        m = INST_RE.match(line)
        if not m:
            continue
        pkg, current, new, origin = m.groups()
        is_security = "security" in origin.lower()
        results.append((pkg, current, new, is_security))
    return results


def main():
    updates = pending_updates()
    security = [u for u in updates if u[3]]
    print(f"# Pending apt updates: {len(updates)} total, {len(security)} security")
    for pkg, current, new, _ in security:
        print(f"SECURITY\t{pkg}\t{current}\t->\t{new}")
    sys.exit(1 if security else 0)


if __name__ == "__main__":
    main()
