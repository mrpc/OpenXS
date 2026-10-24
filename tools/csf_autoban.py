"""Attempts a CSF auto-ban for a watch-daemon finding in a high-confidence
category (yara_exploit/virus/maldet) - only when there's an exact,
unambiguous correlation to a single recent uploader IP. Never guesses:
zero or multiple candidate IPs in the attribution window means no ban,
just a log line (see openxs-watchd.py's call site). Never bans a
Cloudflare edge IP even if attribution somehow points at one (mod_remoteip
not installed, or misconfigured for that specific vhost) - see
cloudflare_ranges.py, the actual safety net this all rests on.

Deliberately watch-daemon-only, never the batch/scheduled scan - the
daemon reacts within seconds of the file actually changing (inotify),
which is what makes a tight access-log correlation window meaningful at
all. A batch scan has no such timing signal - a flagged file could have
existed, unscanned, for hours or days, so there's no "recent request"
to correlate against in the first place.
"""
import os
import re
import subprocess
import time

import cloudflare_ranges

ACCESS_LOG_DIR = "/var/log/virtualmin"
# Virtualmin's own combined-log format: IP - - [timestamp] "METHOD ..."
ACCESS_LOG_LINE_RE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) ')
ACCESS_LOG_TS_FORMAT = "%d/%b/%Y:%H:%M:%S"  # the UTC offset is stripped before parsing - see below

_domain_cache = {}  # username -> domain (or None), for this process's lifetime - doesn't change often


def _domain_for_user(username):
    """Virtualmin's own authoritative username->domain lookup - not a
    guessed naming convention (an account's username doesn't always
    derive predictably from its domain, e.g. after a rename)."""
    if username in _domain_cache:
        return _domain_cache[username]
    try:
        out = subprocess.run(["virtualmin", "list-domains", "--user", username, "--name-only"],
                              capture_output=True, text=True, timeout=10).stdout.strip()
        domain = out.splitlines()[0] if out else None
    except Exception:
        domain = None
    _domain_cache[username] = domain
    return domain


def _username_from_path(fname):
    m = re.match(r"^/home/([^/]+)/", fname)
    return m.group(1) if m else None


def find_unambiguous_recent_uploader_ip(fname, window_seconds=15, now=None, log_dir=None):
    """Returns a single IP only when exactly one distinct client made a
    POST/PUT request to this account's domain within window_seconds of
    now - None (never acted on) for zero or multiple candidates, an
    unresolvable account/domain, a missing log, or a candidate that
    turns out to be a Cloudflare edge IP itself."""
    username = _username_from_path(fname)
    if not username:
        return None
    domain = _domain_for_user(username)
    if not domain:
        return None
    log_path = os.path.join(log_dir or ACCESS_LOG_DIR, f"{domain}_access_log")
    if not os.path.isfile(log_path):
        return None

    now = now if now is not None else time.time()
    try:
        # The window is seconds, not hours - tailing the last 500 lines
        # is already generous for "what happened just now" on any site
        # that isn't under an active, extreme flood.
        out = subprocess.run(["tail", "-n", "500", log_path], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None

    candidates = set()
    for line in out.splitlines():
        m = ACCESS_LOG_LINE_RE.match(line)
        if not m or m.group("method") not in ("POST", "PUT"):
            continue
        # Strip the trailing " +0300"-style UTC offset and parse as
        # local time - every server here runs in the same timezone the
        # offset already implies, so this is equivalent to a proper
        # timezone-aware parse without needing one.
        ts_text = m.group("ts").rsplit(" ", 1)[0]
        try:
            ts = time.mktime(time.strptime(ts_text, ACCESS_LOG_TS_FORMAT))
        except ValueError:
            continue
        if abs(now - ts) <= window_seconds:
            candidates.add(m.group("ip"))

    if len(candidates) != 1:
        return None
    ip = next(iter(candidates))
    if cloudflare_ranges.is_cloudflare_ip(ip):
        return None
    return ip


def ban(ip, reason, ttl="3d"):
    """Temporary ban (reversible - `csf -dr <ip>` undoes it, or it
    expires on its own), not permanent - an automated action should
    stay easy to undo even when the correlation was exact. Returns
    True/False, never raises (CSF missing/misbehaving just means no
    ban happened, not a crash of the caller)."""
    try:
        result = subprocess.run(["csf", "-td", ip, ttl, reason], capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False
