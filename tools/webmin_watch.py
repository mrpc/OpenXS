#!/usr/bin/env python3
"""One job for openxs_collector.py's periodic run: spots Usermin/Webmin
persistence and suspicious logins, independent of sasl_watch.py's own
SMTP-focused checks.

Why: found live 2026-11-10, auditing a compromised SASL account - the same
attacker had also logged into Usermin and set a password-recovery address
(~/.usermin/changepass/recovery). With Usermin's forgot_pass=1 that address
could have let them retake the account even after the stolen password was
changed. Nothing was watching for this; it was only caught by a manual,
one-off audit.

Two independent checks, both alert-only (no auto-action - unlike
sasl_watch.py, there's no known-compromised account yet to block here):

1. Persistence: a fixed, small set of well-known per-home files Usermin
   (or a shell/mail client) lets an account holder create - not a full
   scan of /home (that's pmf_scan.py's job; this stays a handful of
   filenames per Unix account so it's fast enough for the 5-minute
   collector). A sha256 of each present file is kept in STATE_FILE. The
   very first time a path is observed (fresh deploy, or an account that
   didn't exist before) it's baselined silently - whatever it already
   contains is trusted as the pre-monitoring state, same adoption
   philosophy as sasl_watch.py's own "entries already in the map are
   adopted on first sight". Any CHANGE after that - including a
   previously-empty recovery file becoming non-empty - is the finding.
   Watched: ~/.usermin/changepass/recovery, ~/.usermin/{forward,filter,
   fetchmail,schedule,cron}, and the plain ~/.forward/.procmailrc/
   .fetchmailrc a shell account could use the same way.

2. Logins: Usermin's and Webmin's own miniserv.log ("<ip> - <user> [date]
   \"<method> <path> ...\" <status> <bytes>", "-" for user on a failed/
   anonymous request). For each (service, user) pair, the first run
   baselines whatever IPs already logged in during the lookback window
   silently; afterwards, a login from an IP never seen before for that
   user is the finding. Deliberately IP-identity only, not a request-rate
   threshold: the same authenticated user can poll a page every few
   seconds (seen live: webmin's xhr.cgi), which would swamp any
   count-based check with false positives.

Neither check cross-references sasl_watch.py's own flagged IPs yet (a
later enhancement, not implemented here).

Still runnable standalone: python3 webmin_watch.py (no arguments = one run)
"""
import datetime
import hashlib
import json
import os
import pwd
import re
import subprocess
import sys
import time

CONFIG_FILE = os.environ.get("OPENXS_CONFIG", "/etc/openxs/openxs.conf")
STATE_FILE = os.environ.get("OPENXS_WEBMIN_WATCH_STATE", "/var/lib/openxs/webmin_watch.json")
DEFAULTS = {"EMAIL": "root@localhost"}

# Relative to each home directory.
WATCHED_RELPATHS = [
    os.path.join(".usermin", "changepass", "recovery"),
    os.path.join(".usermin", "forward"),
    os.path.join(".usermin", "filter"),
    os.path.join(".usermin", "fetchmail"),
    os.path.join(".usermin", "schedule"),
    os.path.join(".usermin", "cron"),
    ".forward",
    ".procmailrc",
    ".fetchmailrc",
]
MAX_HASH_BYTES = 65536

LOGIN_SOURCES = {
    "Usermin": "/var/usermin/miniserv.log",
    "Webmin": "/var/webmin/miniserv.log",
}
LOGIN_LOOKBACK_HOURS = 24
_LOGIN_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<date>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+)'
)


def load_config(path=None):
    conf = dict(DEFAULTS)
    try:
        with open(path or CONFIG_FILE, encoding="utf-8", errors="replace") as f:
            for line in f:
                key, sep, value = line.strip().partition("=")
                if sep and key in conf and value:
                    conf[key] = value
    except OSError:
        pass
    return conf


def _load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE + ".tmp", "w") as f:
        json.dump(state, f)
    os.replace(STATE_FILE + ".tmp", STATE_FILE)


def _homes():
    """Unix accounts' home directories under /home - both domain owners
    and Virtualmin's per-mailbox subusers (x@d/x-d/x.d), which get real
    Unix accounts too (see sasl_watch.py's _local_users). System/service
    accounts elsewhere (/root, /var/..., no home) are not in scope."""
    seen = set()
    for pw in pwd.getpwall():
        if pw.pw_dir.startswith("/home/") and pw.pw_dir not in seen:
            seen.add(pw.pw_dir)
            yield pw.pw_name, pw.pw_dir


def _safe_hash(home, relpath, max_bytes=MAX_HASH_BYTES):
    """sha256 of relpath under home, or None if absent/unsafe to read.
    Opened O_NOFOLLOW (a user's own symlink must not make root read or
    hash some other file), and the containing directory must resolve
    under home - the same safety shape as sasl_watch.py's own
    _remove_recovery, generalized to any of the watched relpaths."""
    path = os.path.join(home, relpath)
    try:
        real_home = os.path.realpath(home)
        want_dir = os.path.join(real_home, os.path.dirname(relpath)) if os.path.dirname(relpath) else real_home
        if os.path.realpath(os.path.dirname(path)) != want_dir:
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not (st.st_mode & 0o170000) == 0o100000:  # S_ISREG
                return None
            return hashlib.sha256(f.read(max_bytes)).hexdigest()
    except OSError:
        return None


def check_persistence(state):
    """Returns a list of (user, home, relpath) findings, and updates
    state["persistence"] in place (baseline-on-first-sight, see module
    docstring)."""
    store = state.setdefault("persistence", {})
    findings = []
    for user, home in _homes():
        for relpath in WATCHED_RELPATHS:
            key = f"{home}:{relpath}"
            digest = _safe_hash(home, relpath)
            prev = store.get(key)
            if digest is None:
                store.pop(key, None)
                continue
            if prev is None:
                store[key] = digest  # first sighting: trust it, don't alert
            elif prev != digest:
                store[key] = digest
                findings.append((user, home, relpath))
    return findings


def _parse_login_ts(date_str):
    try:
        return datetime.datetime.strptime(date_str, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None


def _login_lines(path, now, lookback_hours):
    try:
        if now - os.path.getmtime(path) > lookback_hours * 3600 + 3600:
            return
        with open(path, encoding="utf-8", errors="replace") as f:
            yield from f
    except OSError:
        return


def check_logins(state, now=None):
    """Returns a list of (service, user, ip) findings - a login from an IP
    never seen before for that (service, user), once a baseline already
    exists for it. Updates state["logins"] in place."""
    now = now if now is not None else time.time()
    cutoff = now - LOGIN_LOOKBACK_HOURS * 3600
    store = state.setdefault("logins", {})
    seen_now = {}
    for service, path in LOGIN_SOURCES.items():
        for line in _login_lines(path, now, LOGIN_LOOKBACK_HOURS):
            m = _LOGIN_RE.match(line)
            if not m or m.group("user") == "-":
                continue
            ts = _parse_login_ts(m.group("date"))
            if ts is None or ts < cutoff:
                continue
            key = f"{service}:{m.group('user')}"
            seen_now.setdefault(key, set()).add(m.group("ip"))

    findings = []
    for key, ips in seen_now.items():
        service, _, user = key.partition(":")
        known = set(store.get(key, []))
        if key not in store:
            store[key] = sorted(ips)  # first sighting: baseline, don't alert
            continue
        new_ips = ips - known
        if new_ips:
            store[key] = sorted(known | ips)
            for ip in sorted(new_ips):
                findings.append((service, user, ip))
    return findings


def _send(conf, subject, body):
    host = subprocess.run(["hostname", "-f"], capture_output=True, text=True).stdout.strip() or "?"
    subprocess.run(["mail", "-s", f"[{host}] OpenXS: {subject}", conf["EMAIL"]],
                   input=body, text=True, timeout=60, check=False)


def run(now=None, conf=None):
    """Returns a short human-readable status string."""
    now = now if now is not None else time.time()
    conf = conf or load_config()
    state = _load_state()
    before = json.dumps(state, sort_keys=True)

    persistence = check_persistence(state)
    for user, home, relpath in persistence:
        _send(conf, f"Usermin/mail persistence file changed for {user}",
              f"'{relpath}' changed under {home} (account: {user}).\n"
              f"Check: {os.path.join(home, relpath)}\n"
              "If this is a password-recovery address and wasn't set by the account owner, "
              "treat the account as possibly compromised (see sasl_watch.py).\n")

    logins = check_logins(state, now)
    for service, user, ip in logins:
        _send(conf, f"{service} login for {user} from a new IP",
              f"{user} logged into {service} from {ip}, not seen before for this account "
              f"(last {LOGIN_LOOKBACK_HOURS}h window).\n"
              f"Check: grep {ip} {LOGIN_SOURCES[service]}\n")

    if json.dumps(state, sort_keys=True) != before:
        _save_state(state)
    return f"{len(persistence)} persistence finding(s), {len(logins)} new-IP login(s)"


def main():
    print(run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
