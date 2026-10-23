#!/usr/bin/env python3
"""Correlates a finding's file with Apache/Virtualmin access logs - "who
hit this file, and when" - requested directly so an admin looking at a
Findings entry can decide whether to ban an IP, rather than digging
through logs by hand. Deliberately read-only/advisory: this never bans
anything itself (see ban_ip.cgi for the one-click, human-reviewed
action) - a false match here would otherwise risk banning something
like Googlebot.

Virtualmin convention: /var/log/virtualmin/<domain>_access_log(.N.gz).

Scoped to the finding's own account: found for real on prod-host-3 that
searching every access log on the server (~90 domains) for just the
file's basename took over two minutes and returned 787,615 "hits" -
almost all noise, since a common filename like index.php matches
countless unrelated requests on completely different sites. Only the
derived URL path is searched now (never a bare basename), and only
within the access logs for domains that actually belong to this
file's account (via Apache's own vhost DocumentRoot, not a guess).
"""
import glob
import gzip
import os
import re
import shutil
import subprocess

LOG_DIR = "/var/log/virtualmin"
VHOST_DIR = "/etc/apache2/sites-enabled"
IP_RE = re.compile(rb"^(\S+) \S+ \S+ \[([^\]]+)\] \"(\S+) (\S+)")


def url_path_for(file_path, accounts_dir="/home", subpath="public_html"):
    """/home/<user>/public_html/foo/bar.php -> /foo/bar.php, or None if
    file_path isn't under a recognisable account web root."""
    prefix = f"{accounts_dir.rstrip('/')}/"
    if not file_path.startswith(prefix):
        return None
    rest = file_path[len(prefix):]
    parts = rest.split("/", 1)
    if len(parts) < 2:
        return None
    user, webpath = parts
    if subpath and webpath.startswith(subpath + "/"):
        webpath = webpath[len(subpath) + 1:]
    elif subpath and webpath == subpath:
        webpath = ""
    return "/" + webpath


def _iter_log_lines(path):
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rb") as f:
            for line in f:
                yield line
    except OSError:
        return


def domains_for_user(user, vhost_dir=None):
    """Which domain(s) does this account's Apache vhost actually serve -
    looked up from DocumentRoot, not guessed from the username (a
    Virtualmin sub-server's domain is rarely the same string as the
    Unix account name it lives under)."""
    vhost_dir = vhost_dir or VHOST_DIR
    domains = []
    try:
        confs = glob.glob(os.path.join(vhost_dir, "*.conf"))
    except OSError:
        return domains
    needle = f"/home/{user}/"
    for conf in confs:
        try:
            with open(conf, errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        if needle in content:
            domains.append(os.path.basename(conf)[:-len(".conf")])
    return domains


def find_access_log_hits(file_path, accounts_dir="/home", subpath="public_html",
                          vhost_dir=None, log_dir=None):
    """Returns a list of (ip, timestamp, method, matched_path, logfile)
    tuples, most recent first. Only searches the derived URL path (never
    a bare basename - too likely to match unrelated requests on other
    sites), and only within access logs for domains belonging to this
    file's own account."""
    log_dir = log_dir or LOG_DIR
    url_path = url_path_for(file_path, accounts_dir, subpath)
    if not url_path or url_path == "/":
        return []
    needle = url_path.encode()

    prefix = f"{accounts_dir.rstrip('/')}/"
    user = file_path[len(prefix):].split("/", 1)[0] if file_path.startswith(prefix) else None
    domains = domains_for_user(user, vhost_dir) if user else []

    if domains:
        logs = []
        for d in domains:
            logs.extend(glob.glob(os.path.join(log_dir, f"{d}_access_log*")))
    else:
        # No vhost match found (unusual layout, or vhost_dir doesn't
        # exist on this server) - fall back to every log rather than
        # silently searching nothing.
        logs = glob.glob(os.path.join(log_dir, "*_access_log*"))

    hits = []
    for logpath in sorted(set(logs)):
        for line in _iter_log_lines(logpath):
            if needle not in line:
                continue
            m = IP_RE.match(line)
            if not m:
                continue
            ip, ts, method, path = m.groups()
            # Exact match (a query string may follow) - a substring
            # check here would also match e.g. /index.php against
            # /some/other/dir/index.php, a real false-positive found
            # while testing.
            if path != needle and not path.startswith(needle + b"?"):
                continue
            hits.append((ip.decode(errors="replace"), ts.decode(errors="replace"),
                          method.decode(errors="replace"), path.decode(errors="replace"),
                          os.path.basename(logpath)))
    hits.reverse()  # logs are chronological; show newest first
    return hits


def summarize_by_ip(hits):
    """hits -> {ip: {"count": N, "first": ts, "last": ts, "sample_path": p}},
    ordered by hit count descending. hits is newest-first (see
    find_access_log_hits), so for a given IP the FIRST occurrence
    encountered in this loop is its most recent (last-seen) hit, and the
    LAST occurrence encountered is its earliest (first-seen) one -
    keep that straight, or the two labels end up swapped."""
    summary = {}
    for ip, ts, method, path, logfile in hits:
        if ip not in summary:
            summary[ip] = {"count": 0, "last": ts, "first": ts, "sample_path": path}
        summary[ip]["count"] += 1
        summary[ip]["first"] = ts  # overwritten every time - ends up as the oldest
    return dict(sorted(summary.items(), key=lambda kv: -kv[1]["count"]))


def ban_ip(ip, reason):
    """CSF if it's installed (keeps the block visible/manageable in the
    same place as every other firewall rule on a CSF-managed server);
    otherwise falls back to a direct iptables DROP rule, since not every
    server this project manages runs CSF. Either way requires root (same
    as every other install_*.py/daemon management in this project).
    Returns (ok, method, message) so the caller can say which firewall
    actually got the rule."""
    if not re.match(r"^[0-9a-fA-F.:]+$", ip):
        return False, None, "Not a valid IP address"
    if shutil.which("csf"):
        try:
            out = subprocess.run(
                ["csf", "-d", ip, reason], capture_output=True, text=True, timeout=15
            )
            return out.returncode == 0, "csf", (out.stdout + out.stderr).strip()
        except Exception as e:
            return False, "csf", str(e)
    if shutil.which("iptables"):
        try:
            # -C first: a ban clicked twice (or an IP already blocked by
            # something else) shouldn't insert a duplicate DROP rule.
            check = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                                    capture_output=True, text=True, timeout=10)
            if check.returncode == 0:
                return True, "iptables", f"{ip} was already blocked"
            out = subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                                  capture_output=True, text=True, timeout=10)
            return out.returncode == 0, "iptables", (out.stdout + out.stderr).strip() or "blocked"
        except Exception as e:
            return False, "iptables", str(e)
    return False, None, "Neither csf nor iptables is available on this server"
