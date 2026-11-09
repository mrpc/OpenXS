#!/usr/bin/env python3
"""One job for openxs_collector.py's periodic run: spots a compromised
SASL/SMTP account from Postfix's mail.log, and a dead milter.

Why: lfd/CSF only count FAILED SMTP AUTH. A stolen password used by a
botnet is a stream of SUCCESSFUL logins - typically low and slow (a
handful per IP, hundreds of IPs a day), which nothing else alerts on
until the spam bounces start piling up somewhere. Found live: weeks of
that, then one IP doing tens of thousands of logins in a day, noticed
only via a third party's rate limit on the bounces.

Per account it alerts when any of these trips (windows are rolling). Login
names are folded into the local account they authenticate as, so 'x' and
'x@domain' (saslauthd -r) count together and are blocked/unblocked together:
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
so when it isn't referenced. With SASL_WATCH_NOTIFY=1 (default) the
account itself and its Virtualmin domain's contact address get a short
notice (template: /etc/openxs/sasl_blocked_notice.txt, subject on line 1).
A blocked account stays blocked until the admin unblocks it - a password
change alone doesn't release it by default, since whoever stole the password
can change it themselves (e.g. through Usermin). SASL_WATCH_UNBLOCK_ON_PWCHANGE=1
releases a local account once its /etc/shadow password changes. By hand:
  sasl_watch.py list
  sasl_watch.py unblock <user> [--hours N]   (--hours: blocked again after
                                              N hours)

Same alert is repeated at most once per REPEAT_SECONDS per user/milter.
Still runnable standalone: python3 sasl_watch.py (no arguments = one run)"""
import fnmatch
import hashlib
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
    "SASL_WATCH_NOTIFY": "1",
    "SASL_WATCH_UNBLOCK_ON_PWCHANGE": "0",
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


def analyze(lines, conf, now, not_before=None):
    """Returns ({account: [reason, ...]}, {milter_service: last_seen_ts},
    {account: {login names seen}}). Login names are folded into the local
    account they authenticate as (see account()), so 'x' and 'x@domain'
    logins add up. not_before: {account: ts} - older lines are ignored
    (just unblocked)."""
    not_before = not_before or {}
    shadow = _shadow()
    variants = defaultdict(set)
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
            user = account(m.group("user"), shadow)
            if ts < not_before.get(user, 0):
                continue
            qid_user[m.group("qid")] = user
            variants[user].add(m.group("user"))
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
    return dict(findings), milters, {u: variants[u] for u in findings}


SHADOW_FILE = "/etc/shadow"
VIRTUALMIN_DOMAINS_DIR = "/etc/webmin/virtual-server/domains"
NOTICE_TEMPLATE_FILE = "/etc/openxs/sasl_blocked_notice.txt"
# Subject on the first line, then the body; {user} is replaced. Deliberately
# no links or details: the mailbox's password is known to whoever is
# abusing it, so they can read this too.
DEFAULT_NOTICE = """Ο λογαριασμός σας μπλοκαρίστηκε για αποστολή / Your account was blocked from sending

Λόγω ύποπτης κίνησης, ο λογαριασμός {user} μπλοκαρίστηκε για αποστολή email.
Ο κωδικός του φαίνεται να έχει διαρρεύσει. Αλλάξτε τον το συντομότερο και
επικοινωνήστε με τον διαχειριστή του server για να ενεργοποιηθεί ξανά η
αποστολή. Η λήψη email δεν επηρεάζεται.

Due to suspicious activity, sending email from {user} has been blocked. Its
password appears to have leaked. Please change it as soon as possible and
contact the server administrator to have sending re-enabled. Receiving email
is not affected.
"""


def _shadow():
    """{name: password hash} from /etc/shadow, {} when unreadable."""
    try:
        with open(SHADOW_FILE, encoding="utf-8", errors="replace") as f:
            return {name: rest.split(":", 1)[0] for name, _, rest in (line.partition(":") for line in f)}
    except OSError:
        return {}


def account(login, shadow=None):
    """The local account a SASL login name authenticates as: the name itself
    when it's a Unix user (Virtualmin has both 'x' and 'x@domain' style
    users), else the part before @ when that is one (saslauthd -r appends
    the realm: 'x@domain' logs in as 'x'), else the name unchanged."""
    shadow = _shadow() if shadow is None else shadow
    if login in shadow or "@" not in login:
        return login
    local = login.split("@", 1)[0]
    return local if local in shadow else login


def _map_users(map_path):
    try:
        with open(map_path, encoding="utf-8") as f:
            return [line.split()[0] for line in f if line.strip() and not line.startswith("#")]
    except OSError:
        return []


def _postmap(map_path):
    subprocess.run(["postmap", map_path], check=True, capture_output=True, timeout=30)


def block_user(names, map_path):
    """Adds `name REJECT ...` for each login name of one account to the
    check_sasl_access map and postmaps it. Returns a one-line description
    of what happened, never raises."""
    try:
        present = _map_users(map_path)
        missing = [n for n in sorted(names) if n not in present]
        if missing:
            existing = open(map_path, encoding="utf-8").read() if os.path.exists(map_path) else ""
            with open(map_path, "a", encoding="utf-8") as f:
                if existing and not existing.endswith("\n"):
                    f.write("\n")
                for n in missing:
                    f.write(f"{n} REJECT Account suspended (possible compromise) - contact the server admin\n")
        _postmap(map_path)
        restrictions = subprocess.run(["postconf", "-h", "smtpd_sender_restrictions"],
                                      capture_output=True, text=True, timeout=10).stdout
        note = "" if map_path in restrictions else (
            f" WARNING: {map_path} is not in smtpd_sender_restrictions, so the block has no effect yet.")
        return f"AUTO-BLOCKED: {', '.join(sorted(names))} in {map_path} (undo: sasl_watch.py unblock {min(names)}).{note}"
    except Exception as e:
        return f"AUTO-BLOCK FAILED: {e}"


def remove_from_map(acct, map_path):
    """Removes every login name of that account."""
    shadow = _shadow()
    with open(map_path, encoding="utf-8") as f:
        lines = f.readlines()
    with open(map_path, "w", encoding="utf-8") as f:
        f.writelines(line for line in lines if not line.split() or account(line.split()[0], shadow) != acct)
    _postmap(map_path)


def password_fingerprint(user):
    """sha256 of the user's /etc/shadow hash (never the hash itself, so the
    state file stays harmless), or None when the SASL name isn't a local
    account - then a password change can't be detected."""
    h = _shadow().get(account(user))
    return hashlib.sha256(h.encode()).hexdigest() if h is not None else None


def _domain_contacts(user):
    """Virtualmin's contact address for the domain the user belongs to:
    the mailbox's own domain for user@domain, else the domain whose Unix
    owner is this user."""
    domain = user.split("@", 1)[1].lower() if "@" in user else None
    try:
        names = os.listdir(VIRTUALMIN_DOMAINS_DIR)
    except OSError:
        return []
    for name in names:
        if not name.isdigit():
            continue
        d = {}
        try:
            with open(os.path.join(VIRTUALMIN_DOMAINS_DIR, name), encoding="utf-8", errors="replace") as f:
                for line in f:
                    k, _, v = line.rstrip("\n").partition("=")
                    d[k] = v
        except OSError:
            continue
        if (domain and d.get("dom", "").lower() == domain) or (not domain and d.get("user") == user and not d.get("parent")):
            addr = d.get("emailto") or d.get("email")
            return [addr] if addr else []
    return []


def notice_recipients(names, conf):
    rcpts = []
    for n in sorted(names):
        for a in ([n] if "@" in n else []) + _domain_contacts(n):
            if a not in rcpts:
                rcpts.append(a)
    return rcpts or [conf["EMAIL"]]


def notify_user(user, names, conf):
    """Local delivery through sendmail (pickup, never SASL). Returns the
    recipients, or an error string."""
    try:
        template = open(NOTICE_TEMPLATE_FILE, encoding="utf-8").read().strip() or DEFAULT_NOTICE
    except OSError:
        template = DEFAULT_NOTICE
    subject, _, body = template.replace("{user}", user).partition("\n")
    rcpts = notice_recipients(names, conf)
    msg = (f"To: {', '.join(rcpts)}\nSubject: {subject.strip()}\nMIME-Version: 1.0\n"
           f"Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n{body.lstrip(chr(10))}")
    try:
        subprocess.run(["/usr/sbin/sendmail", "-t", "-oi"], input=msg.encode(), check=True, timeout=60)
        return "notified " + ", ".join(rcpts)
    except Exception as e:
        return f"notice to the account FAILED: {e}"


def _load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def _send(conf, subject, body):
    host = subprocess.run(["hostname", "-f"], capture_output=True, text=True).stdout.strip() or "?"
    subprocess.run(["mail", "-s", f"[{host}] OpenXS: {subject}", conf["EMAIL"]],
                   input=body, text=True, timeout=60, check=False)


def _map_accounts(map_path):
    """{account: [login names in the map]}."""
    shadow = _shadow()
    out = defaultdict(list)
    for n in _map_users(map_path):
        out[account(n, shadow)].append(n)
    return dict(out)


def _manage_blocked(state, conf, now):
    """Re-blocks expired temporary unblocks. With
    SASL_WATCH_UNBLOCK_ON_PWCHANGE=1, first releases accounts whose password
    changed (temporarily unblocked ones included). Entries added to the map
    by hand are adopted on first sight, so they're handled the same way."""
    on_pwchange = conf["SASL_WATCH_UNBLOCK_ON_PWCHANGE"] == "1"
    blocked = state.setdefault("blocked", {})
    for acct, names in _map_accounts(conf["SASL_WATCH_MAP"]).items():
        if acct not in blocked:
            blocked[acct] = {"since": now, "reason": "manual", "pw": password_fingerprint(acct), "names": names}
    for acct, b in list(blocked.items()):
        fp = password_fingerprint(acct)
        if on_pwchange and b.get("pw") and fp and fp != b["pw"]:
            remove_from_map(acct, conf["SASL_WATCH_MAP"])
            del blocked[acct]
            state.setdefault("not_before", {})[acct] = now
            _send(conf, f"mail account {acct} unblocked (password changed)",
                  f"The password of '{acct}' changed, so it was removed from {conf['SASL_WATCH_MAP']}.\n")
        elif b.get("until") and now >= b["until"]:
            result = block_user(b.get("names") or [acct], conf["SASL_WATCH_MAP"])
            if result.startswith("AUTO-BLOCKED"):
                del b["until"]
            _send(conf, f"mail account {acct} blocked again (temporary unblock expired)",
                  f"The temporary unblock of '{acct}' expired and its password hasn't changed.\n{result}\n")


def run(now=None, conf=None):
    """Returns a short human-readable status string."""
    now = now if now is not None else time.time()
    conf = conf or load_config()
    if not os.path.exists(conf["MAIL_LOG"]):
        return f"no {conf['MAIL_LOG']}, skipped"
    state = _load_state()
    before = json.dumps(state, sort_keys=True)
    _manage_blocked(state, conf, now)
    blocked = state["blocked"]
    findings, milters, variants = analyze(_log_lines(conf["MAIL_LOG"], now), conf, now, state.get("not_before", {}))
    sent = 0
    for acct, reasons in findings.items():
        key = f"user:{acct}"
        if acct in blocked and not blocked[acct].get("until"):
            continue  # already blocked: its botnet logins keep showing up, nothing new to say
        if now - state.get(key, 0) < REPEAT_SECONDS:
            continue
        names = sorted(variants[acct] | {acct})
        body = [f"SASL account '{acct}' looks compromised (possible stolen password used for spam):", ""]
        body += [f"  - {r}" for r in reasons]
        body += ["", f"Login names seen: {', '.join(sorted(variants[acct]))}",
                 "Check: grep 'sasl_username=" + acct + "' " + conf["MAIL_LOG"]]
        if acct in blocked:
            body += ["", f"Not re-blocked: temporarily unblocked until {time.strftime('%Y-%m-%d %H:%M', time.localtime(blocked[acct]['until']))}."]
        elif conf["SASL_WATCH_AUTOBLOCK"] == "1":
            result = block_user(names, conf["SASL_WATCH_MAP"])
            body += ["", result]
            if result.startswith("AUTO-BLOCKED"):
                blocked[acct] = {"since": now, "reason": "; ".join(reasons), "pw": password_fingerprint(acct), "names": names}
                if conf["SASL_WATCH_UNBLOCK_ON_PWCHANGE"] == "1" and blocked[acct]["pw"] is None:
                    body += ["Not a local account, so a password change can't be detected: unblock by hand."]
                if conf["SASL_WATCH_NOTIFY"] == "1":
                    body += [notify_user(acct, names, conf)]
        else:
            body += ["", "Not blocked (SASL_WATCH_AUTOBLOCK=0). Change the password; to stop it sending meanwhile, add",
                     f"'<name> REJECT' for each of {', '.join(names)} to {conf['SASL_WATCH_MAP']} (check_sasl_access) and postmap it."]
        _send(conf, f"possible compromised mail account {acct}", "\n".join(body) + "\n")
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
    if json.dumps(state, sort_keys=True) != before:
        _save_state(state)
    return f"{len(findings)} suspicious SASL account(s), {len(milters)} dead milter(s), {sent} alert(s) sent"


def cmd_list(conf):
    """One tab-separated line per blocked account: account, since, until,
    reason. Map entries not seen by a run yet show as 'manual'."""
    blocked = _load_state().get("blocked", {})
    fmt = lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else ""
    accts = list(_map_accounts(conf["SASL_WATCH_MAP"]))
    accts += [a for a in blocked if a not in accts]  # temporarily unblocked
    for a in accts:
        b = blocked.get(a, {})
        print("\t".join([a, fmt(b.get("since")), fmt(b.get("until")), b.get("reason", "manual")]))


def cmd_unblock(user, hours, conf, now=None):
    """user: any login name of the account - all of its names are unblocked."""
    now = now if now is not None else time.time()
    acct = account(user)
    state = _load_state()
    blocked = state.setdefault("blocked", {})
    in_map = _map_accounts(conf["SASL_WATCH_MAP"])
    if acct not in in_map and acct not in blocked:
        return f"{acct} is not blocked"
    remove_from_map(acct, conf["SASL_WATCH_MAP"])
    if hours:
        b = blocked.setdefault(acct, {"since": now, "reason": "manual", "pw": password_fingerprint(acct)})
        b.setdefault("names", in_map.get(acct) or [acct])
        b["until"] = now + hours * 3600
        msg = f"{acct} unblocked for {hours:g}h, blocked again after that"
    else:
        blocked.pop(acct, None)
        msg = f"{acct} unblocked"
    # Don't let the same 24h of log lines re-block it on the next run.
    state.setdefault("not_before", {})[acct] = now
    _save_state(state)
    return msg


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Compromised SASL account watch (see module docstring).")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list", help="blocked accounts: user, since, temporary-unblock end, reason")
    u = sub.add_parser("unblock", help="remove from the map (for good, or for --hours)")
    u.add_argument("user")
    u.add_argument("--hours", type=float, default=0)
    args = ap.parse_args(argv)
    conf = load_config()
    if args.cmd == "list":
        cmd_list(conf)
    elif args.cmd == "unblock":
        print(cmd_unblock(args.user, args.hours, conf))
    else:
        print(run(conf=conf))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
