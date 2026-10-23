#!/usr/bin/env python3
"""Summarizes recent ModSecurity 'Access denied' blocks across every
Apache error log on the box - both the shared /var/log/apache2/error.log
and (on a Virtualmin install) each domain's own
/var/log/virtualmin/<domain>_error_log, since Virtualmin routes each
vhost's errors to its own file rather than the shared one.

Grouped by (hostname, uri, rule id) with a count and first/last seen
time, so a repeated block on one real endpoint (worth investigating -
either a real false positive, or an underlying app bug ModSecurity is
correctly catching, as happened for real on babysitter.gr) stands out
from one-off attack-scanner noise (many different URIs, few hits each)."""
import glob
import re
import subprocess
from collections import defaultdict

BLOCK_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\].*ModSecurity: Access denied.*"
    r'\[id "(?P<id>\d+)"\]'
)
HOST_RE = re.compile(r'\[hostname "([^"]*)"\]')
URI_RE = re.compile(r'\[uri "([^"]*)"\]')


def log_files():
    files = set(glob.glob("/var/log/apache2/error.log"))
    files |= set(glob.glob("/var/log/virtualmin/*_error_log"))
    return sorted(files)


def summarize(max_rows=50):
    groups = {}
    cmd = ["grep", "-h", "-r", "ModSecurity: Access denied"] + log_files()
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    for line in out.splitlines():
        m = BLOCK_RE.search(line)
        if not m:
            continue
        hm = HOST_RE.search(line)
        um = URI_RE.search(line)
        key = (hm.group(1) if hm else "(unknown)", um.group(1) if um else "", m.group("id"))
        g = groups.setdefault(key, {"count": 0, "first": m.group("ts"), "last": m.group("ts")})
        g["count"] += 1
        g["last"] = m.group("ts")
    rows = [
        {"host": h, "uri": u, "rule_id": r, **g}
        for (h, u, r), g in groups.items()
    ]
    rows.sort(key=lambda r: -r["count"])
    return rows[:max_rows]


if __name__ == "__main__":
    for row in summarize():
        print(f"{row['count']:>5}  {row['host']:<30} {row['uri']:<40} rule {row['rule_id']}")
