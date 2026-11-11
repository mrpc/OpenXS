#!/usr/bin/env python3
"""Checks whether this server has any WordPress install at all - used by
install_modsecurity.sh to decide whether the wp-upgrade-rce.conf rule
(CVE-2026-119977) is worth installing. Same reasoning as
php2shell_check.py: zero benefit, only extra WAF surface, on a server
with nothing it could ever protect.
"""
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import version_scan

CONFIG_FILE = os.environ.get("OPENXS_CONFIG", "/etc/openxs/openxs.conf")
DEFAULTS = {"SCAN_MODE": "", "ACCOUNTS_DIR": "/home", "ACCOUNTS_SUBPATH": "", "SCAN_PATH": "/var/www"}


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


def scan_roots(conf):
    if conf["SCAN_MODE"] == "accounts":
        pattern = os.path.join(conf["ACCOUNTS_DIR"], "*", conf["ACCOUNTS_SUBPATH"]) \
            if conf["ACCOUNTS_SUBPATH"] else os.path.join(conf["ACCOUNTS_DIR"], "*")
        return glob.glob(pattern)
    return [conf["SCAN_PATH"]]


def any_wordpress_installed(conf):
    for root in scan_roots(conf):
        if os.path.isdir(root) and next(version_scan.find_wordpress_installs(root), None):
            return True
    return False


def main():
    if any_wordpress_installed(load_config()):
        print("# WordPress install(s) found")
        sys.exit(1)
    print("# No WordPress install found - skipping wp-upgrade-rce ModSecurity rule")
    sys.exit(0)


if __name__ == "__main__":
    main()
