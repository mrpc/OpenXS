"""Home directories of sites the hosting panel has disabled/suspended.

A disabled site isn't served, so some checks are pure noise or waste for
it: an outdated CMS version can't be exploited over the web, its mail
isn't delivered, and nothing writes to it (real-time watches only cost
inotify memory). Those checks (version_scan.py, mailbox_scan.py,
openxs-watchd.py) skip these homes. The nightly malware scan does NOT:
the files are still on disk and come back to life if the site is
re-enabled or the account moved - backdoors in disabled sites are exactly
what got quarantined on 2026-11-08.

Sources (none present = nothing is disabled, behavior unchanged):
  - Virtualmin: /etc/webmin/virtual-server/domains/<id>, key=value lines;
    `disabled=` lists the disabled features (e.g. unix,dns,mail,web,ssl,
    mysql) - a site counts as disabled when `web` is among them.
  - cPanel: /var/cpanel/suspended/<user> exists.
"""
import glob
import os
import pwd

VIRTUALMIN_DOMAINS = "/etc/webmin/virtual-server/domains"
CPANEL_SUSPENDED = "/var/cpanel/suspended"


def _virtualmin_homes(domains_dir):
    homes, active = set(), set()
    for path in glob.glob(os.path.join(domains_dir, "*")):
        cfg = {}
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    k, sep, v = line.rstrip("\n").partition("=")
                    if sep:
                        cfg[k] = v
        except OSError:
            continue
        home = cfg.get("home", "").rstrip("/")
        if not home:
            continue
        if "web" in cfg.get("disabled", "").split(","):
            homes.add(home)
        else:
            active.add(home)
    # Alias/sub-domain files carry their own disabled= but can share a home
    # with a live domain - never skip a home any active domain still uses.
    return homes - active


def _cpanel_homes(suspended_dir):
    homes = set()
    try:
        users = os.listdir(suspended_dir)
    except OSError:
        return homes
    for user in users:
        try:
            homes.add(pwd.getpwnam(user).pw_dir.rstrip("/"))
        except KeyError:
            pass
    return homes


def disabled_homes(domains_dir=VIRTUALMIN_DOMAINS, suspended_dir=CPANEL_SUSPENDED):
    return _virtualmin_homes(domains_dir) | _cpanel_homes(suspended_dir)


def is_disabled(path, homes):
    path = path.rstrip("/")
    return any(path == h or path.startswith(h + "/") for h in homes)


def walk(root, homes):
    """os.walk(root) that never descends into a disabled home."""
    if is_disabled(root, homes):
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d).rstrip("/") not in homes]
        yield dirpath, dirnames, filenames

