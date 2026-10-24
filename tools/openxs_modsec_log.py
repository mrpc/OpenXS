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
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

CACHE_PATH = os.environ.get("OPENXS_MODSEC_CACHE", "/var/lib/openxs/modsec_summary.json")

BLOCK_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\].*ModSecurity: Access denied.*"
    r'\[id "(?P<id>\d+)"\]'
)
HOST_RE = re.compile(r'\[hostname "([^"]*)"\]')
URI_RE = re.compile(r'\[uri "([^"]*)"\]')

# Apache error log's own timestamp format, e.g. "Sat Oct 24 01:43:36.376503 2026"
TS_FORMAT = "%a %b %d %H:%M:%S.%f %Y"


def log_files():
    files = set(glob.glob("/var/log/apache2/error.log"))
    files |= set(glob.glob("/var/log/virtualmin/*_error_log"))
    return sorted(files)


def _matching_lines():
    """Yields (line, host, uri, rule_id, ts) for every ModSecurity block
    line found - the shared parse step both summarize() and
    daily_counts() build on."""
    cmd = ["grep", "-h", "-r", "ModSecurity: Access denied"] + log_files()
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    for line in out.splitlines():
        m = BLOCK_RE.search(line)
        if not m:
            continue
        hm = HOST_RE.search(line)
        um = URI_RE.search(line)
        yield (hm.group(1) if hm else "(unknown)", um.group(1) if um else "", m.group("id"), m.group("ts"))


def summarize(max_rows=50):
    groups = {}
    for host, uri, rule_id, ts in _matching_lines():
        key = (host, uri, rule_id)
        g = groups.setdefault(key, {"count": 0, "first": ts, "last": ts})
        g["count"] += 1
        g["last"] = ts
    rows = [
        {"host": h, "uri": u, "rule_id": r, **g}
        for (h, u, r), g in groups.items()
    ]
    rows.sort(key=lambda r: -r["count"])
    return rows[:max_rows]


def daily_counts():
    """{date (YYYY-MM-DD): block count} - for the Stats page's existing
    per-day chart/table, same date format as openxs_db.daily_stats_filled().
    A line whose timestamp doesn't parse (unexpected log format) is
    skipped rather than crashing the whole page over one bad line."""
    counts = {}
    for _host, _uri, _rule_id, ts in _matching_lines():
        try:
            date = datetime.strptime(ts, TS_FORMAT).date().isoformat()
        except ValueError:
            continue
        counts[date] = counts.get(date, 0) + 1
    return counts


def write_cache(path=CACHE_PATH):
    """Run by cron (install_modsecurity.sh, every 5 min) so the Webmin
    page reads a file instead of re-grepping every Apache error log on
    the box on every single page view - the same "expensive scan once,
    cheap read many times" split openxs_modsec_record.py already does
    for the daily-counts history, just on a tighter interval since this
    view is meant to show *recent* blocks."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = {"generated_at": time.time(), "rows": summarize()}
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f)
    os.replace(tmp_path, path)  # atomic - a reader never sees a half-written file


def main():
    if "--write-cache" in sys.argv:
        write_cache()
        return
    # Tab-separated, one row per line - meant to be parsed (by the Webmin
    # CGI, so it can render a real table with a per-rule lookup link),
    # not read directly as formatted CLI output.
    for row in summarize():
        print(f"{row['count']}\t{row['host']}\t{row['uri']}\t{row['rule_id']}\t{row['first']}\t{row['last']}")


if __name__ == "__main__":
    main()
