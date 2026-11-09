#!/usr/bin/env python3
"""One job for openxs_collector.py's periodic run: spots a compromised
SASL/SMTP account from Postfix's mail.log, and a dead milter.

Why: lfd/CSF only count FAILED SMTP AUTH. A stolen password used by a
botnet is a stream of SUCCESSFUL logins - typically low and slow (a
handful per IP, hundreds of IPs a day), which nothing else alerts on
until the spam bounces start piling up somewhere. Found live: weeks of
that, then one IP doing tens of thousands of logins in a day, noticed
only via a third party's rate limit on the bounces.

Per SASL user, it alerts when any of these trips (windows are rolling):
  - distinct client IPs in 24h > SASL_WATCH_MAX_IPS - IPs whose
    (forward-confirmed - Postfix prints "unknown" otherwise) reverse
    hostname matches SASL_WATCH_EXEMPT_HOSTS don't count, e.g. Gmail's
    "send mail as" relaying through its own fleet of mail-*.google.com;
  - messages submitted in the last hour > SASL_WATCH_MAX_MSGS_PER_HOUR;
  - bounced share of its delivered mail in 24h > SASL_WATCH_MAX_BOUNCE_PCT
    (only once at least BOUNCE_MIN_SAMPLE deliveries were seen).
Also alerts when a milter in smtpd_milters refuses connections (a dead
milter means its rate limits/greylisting silently stop applying).

SASL_WATCH_AUTOBLOCK=1 (off by default) also adds the user as REJECT to
SASL_WATCH_MAP (a check_sasl_access map, default /etc/postfix/sasl_blocked)
and runs postmap. That only has an effect when main.cf actually uses the
map (first in smtpd_sender_restrictions, and in whatever restriction
class the submission/smtps services in master.cf use) - the alert says
so when it isn't referenced. Undo: delete the line, postmap again.

Same alert is repeated at most once per REPEAT_SECONDS per user/milter.
Still runnable standalone: python3 sasl_watch.py"""
import fnmatch
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict

CONFIG_FILE = os.environ.get("OPENXS_CONFIG", "/etc/openxs/openxs.conf")
STATE_FILE = os.environ.get("OPENXS_SASL_WATCH_STATE", "/var/lib/openxs/sasl_watch.json")
DEFAULTS = {
    "EMAIL": "root@localhost",
    "MAIL_LOG": "/var/log/mail.log",
    "SASL_WATCH_MAX_IPS": "10",
    "SASL_WATCH_MAX_MSGS_PER_HOUR": "100",
    "SASL_WATCH_MAX_BOUNCE_PCT": "30",
    "SASL_WATCH_EXEMPT_HOSTS": "mail-*.google.com",
    "SASL_WATCH_AUTOBLOCK": "0",
    "SASL_WATCH_MAP": "/etc/postfix/sasl_blocked",
}
DAY = 86400
REPEAT_SECONDS = DAY
BOUNCE_MIN_SAMPLE = 20

# Both the classic "Nov  9 12:00:01" syslog stamp and rsyslog's RFC3339 one
# (Debian trixie's default).
_TS_RE = re.compile(r"^(?:(?P<iso>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\S*|(?P<bsd>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d))\s")
_SASL_RE = re.compile(r"postfix/\S*smtpd\[\d+\]: (?P<qid>\w+): client=(?P<host>[^\[\s]*)\[(?P<ip>[^\]]+)\].*?sasl_username=(?P<user>[^,\s]+)")
_STATUS_RE = re.compile(r"postfix/\S+\[\d+\]: (?P<qid>\w+): to=<.*?status=(?P<status>sent|bounced)\b")
_MILTER_RE = re.compile(r"warning: connect to Milter service (?P<svc>\S+?): Connection refused")


def load_config(path=None):
    conf = dict(DEFAULTS)
    try:
        with open(path or CONFIG_FILE, encoding="utf-8", errors="replace") as f:
            for line in f:
                key, sep, value = line.strip().partition("=")
                # A blank exempt list is a real choice (from the Settings page), other blanks mean "default".
                if sep and key in conf and (value or key == "SASL_WATCH_EXEMPT_HOSTS"):
                    conf[key] = value
    except OSError:
        pass
    return conf


def _parse_ts(line, now):
    m = _TS_RE.match(line)
    if not m:
        return None
    if m.group("iso"):
        # Local time, like the BSD stamp - the offset suffix is ignored, the
        # server's own timezone is what mktime() assumes anyway.
        return time.mktime(time.strptime(m.group("iso"), "%Y-%m-%dT%H:%M:%S"))
    year = time.localtime(now).tm_year
    ts = time.mktime(time.strptime(f"{year} {m.group('bsd')}", "%Y %b %d %H:%M:%S"))
    if ts > now + DAY:  # a December line read in January
        ts = time.mktime(time.strptime(f"{year - 1} {m.group('bsd')}", "%Y %b %d %H:%M:%S"))
    return ts


def _log_lines(mail_log, now):
    # ponytail: rereads mail.log + mail.log.1 in full every run - fine up to a
    # few hundred MB/day; keep a byte offset in STATE_FILE if it gets slower.
    for path in (mail_log + ".1", mail_log):
        try:
            if now - os.path.getmtime(path) > DAY + 3600:
                continue
            with open(path, encoding="utf-8", errors="replace") as f:
                yield from f
        except OSError:
            continue


def analyze(lines, conf, now):
    """Returns ({user: [reason, ...]}, {milter_service: last_seen_ts})."""
    exempt = [p for p in re.split(r"[\s,]+", conf["SASL_WATCH_EXEMPT_HOSTS"]) if p]
    ips = defaultdict(set)
    hourly = defaultdict(int)
    qid_user = {}
    delivered = defaultdict(lambda: {"sent": 0, "bounced": 0})
    milters = {}
    for line in lines:
        if "sasl_username=" not in line and "status=" not in line and "Milter service" not in line:
            continue
        ts = _parse_ts(line, now)
        if ts is None or now - ts > DAY:
            continue
        m = _SASL_RE.search(line)
        if m:
            user = m.group("user")
            qid_user[m.group("qid")] = user
            if not any(fnmatch.fnmatch(m.group("host").lower(), p.lower()) for p in exempt):
                ips[user].add(m.group("ip"))
            if now - ts <= 3600:
                hourly[user] += 1
            continue
        m = _STATUS_RE.search(line)
        if m:
            if m.group("qid") in qid_user:
                delivered[qid_user[m.group("qid")]][m.group("status")] += 1
            continue
        m = _MILTER_RE.search(line)
        if m and now - ts <= 3600:
            milters[m.group("svc")] = ts

    max_ips = int(conf["SASL_WATCH_MAX_IPS"])
    max_msgs = int(conf["SASL_WATCH_MAX_MSGS_PER_HOUR"])
    max_bounce = float(conf["SASL_WATCH_MAX_BOUNCE_PCT"])
    findings = defaultdict(list)
    for user, seen in ips.items():
        if len(seen) > max_ips:
            sample = ", ".join(sorted(seen)[:10])
            findings[user].append(f"logged in from {len(seen)} different IPs in 24h (limit {max_ips}): {sample}{' ...' if len(seen) > 10 else ''}")
    for user, n in hourly.items():
        if n > max_msgs:
            findings[user].append(f"submitted {n} messages in the last hour (limit {max_msgs})")
    for user, d in delivered.items():
        total = d["sent"] + d["bounced"]
        if total >= BOUNCE_MIN_SAMPLE and 100.0 * d["bounced"] / total > max_bounce:
            findings[user].append(f"{d['bounced']} of {total} deliveries bounced in 24h ({100.0 * d['bounced'] / total:.0f}%, limit {max_bounce:g}%)")
    return dict(findings), milters


def block_user(user, map_path):
    """Adds `user REJECT ...` to the check_sasl_access map and postmaps it.
    Returns a one-line description of what happened, never raises."""
    try:
        existing = open(map_path, encoding="utf-8").read() if os.path.exists(map_path) else ""
        if not any(line.split()[:1] == [user] for line in existing.splitlines()):
            with open(map_path, "a", encoding="utf-8") as f:
                if existing and not existing.endswith("\n"):
                    f.write("\n")
                f.write(f"{user} REJECT Account suspended (possible compromise) - contact the server admin\n")
        subprocess.run(["postmap", map_path], check=True, capture_output=True, timeout=30)
        restrictions = subprocess.run(["postconf", "-h", "smtpd_sender_restrictions"],
                                      capture_output=True, text=True, timeout=10).stdout
        note = "" if map_path in restrictions else (
            f" WARNING: {map_path} is not in smtpd_sender_restrictions, so the block has no effect yet.")
        return f"AUTO-BLOCKED: added to {map_path} (remove the line and run postmap to undo).{note}"
    except Exception as e:
        return f"AUTO-BLOCK FAILED: {e}"


def _load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _send(conf, subject, body):
    host = subprocess.run(["hostname", "-f"], capture_output=True, text=True).stdout.strip() or "?"
    subprocess.run(["mail", "-s", f"[{host}] OpenXS: {subject}", conf["EMAIL"]],
                   input=body, text=True, timeout=60, check=False)


def run(now=None, conf=None):
    """Returns a short human-readable status string."""
    now = now if now is not None else time.time()
    conf = conf or load_config()
    if not os.path.exists(conf["MAIL_LOG"]):
        return f"no {conf['MAIL_LOG']}, skipped"
    findings, milters = analyze(_log_lines(conf["MAIL_LOG"], now), conf, now)
    state = _load_state()
    sent = 0
    for user, reasons in findings.items():
        key = f"user:{user}"
        if now - state.get(key, 0) < REPEAT_SECONDS:
            continue
        body = [f"SASL user '{user}' looks compromised (possible stolen password used for spam):", ""]
        body += [f"  - {r}" for r in reasons]
        body += ["", "Check: grep 'sasl_username=" + user + "' " + conf["MAIL_LOG"]]
        if conf["SASL_WATCH_AUTOBLOCK"] == "1":
            body += ["", block_user(user, conf["SASL_WATCH_MAP"])]
        else:
            body += ["", "Not blocked (SASL_WATCH_AUTOBLOCK=0). Change the password; to stop it sending meanwhile, add",
                     f"'{user} REJECT' to {conf['SASL_WATCH_MAP']} (check_sasl_access) and postmap it."]
        _send(conf, f"possible compromised mail account {user}", "\n".join(body) + "\n")
        state[key] = now
        sent += 1
    for svc, ts in milters.items():
        key = f"milter:{svc}"
        if now - state.get(key, 0) < REPEAT_SECONDS:
            continue
        _send(conf, f"milter {svc} is refusing connections",
              f"Postfix could not connect to milter {svc} (last at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}).\n"
              "Whatever it enforces (rate limits, greylisting, DKIM) is NOT applied while it's down.\n"
              "Check: systemctl --failed, and the milter's own log.\n")
        state[key] = now
        sent += 1
    if sent:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    return f"{len(findings)} suspicious SASL user(s), {len(milters)} dead milter(s), {sent} alert(s) sent"


if __name__ == "__main__":
    print(run())
    sys.exit(0)
