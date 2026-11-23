#!/usr/bin/env python3
"""
Wires up CSF's documented regex.custom.pm extension point for two
independent rules, using CSF's existing LF_CUSTOMTRIGGER mechanism. Does
not touch lfd.pl itself, and inserts without clobbering any custom rules
already in the file - each rule is recognized by its own unique marker
(its failure-name string), not a single catch-all check, so adding a
second rule here can't make the first one look "already present".

1. Upload-block (CUSTOM1_LOG, Apache's error.log): lfd picks up our
   mod_security block messages and auto-blocks the offending IP.
2. WordPress brute force (CUSTOM2_LOG, every vhost's access log): plain
   HTTP POSTs to wp-login.php/xmlrpc.php - these always return 200 (no
   failed-auth log line anything else here would catch), and mod_security
   is often DetectionOnly, so nothing was blocking this at all. Found
   live on a production server 2026-11-08 (2,604 such POSTs/24h from 690
   IPs) - a manually-deployed version of this exact rule has been running
   there since, see the Servers repo. Needs an access log to actually
   exist to be worth anything - tried in order: Virtualmin's per-vhost
   logs, plain Apache, cPanel's domlogs; skipped (with a note) if none is
   found. Threshold/ban window are configurable via
   /etc/openxs/openxs.conf's WP_BRUTE_THRESHOLD (default 30/h) and
   WP_BRUTE_BAN_SECS (default 3600) - matches the values already proven
   in production (legitimate traffic, e.g. Jetpack, stays far under 30/h;
   the actual botnets seen were up to ~128/h per IP).
   Deliberately NOT building a CSF-to-Cloudflare bridge for the
   proxied-domains gap this rule can't cover (an IP block never reaches a
   domain behind Cloudflare's proxy) - considered and explicitly rejected
   for this fleet (Cloudflare's IP Access Rules have a cap that automated
   blocks would exhaust); that stays a WordPress/Cloudflare-level concern.

Used both by install.sh (--with-csf-hook) and the Webmin dashboard's
"Install" button (install_csf_hook.cgi) - single source of truth.
"""
import glob
import os
import re
import subprocess
import sys

CSF_CONF = "/etc/csf/csf.conf"
CSF_REGEX = "/etc/csf/regex.custom.pm"
OPENXS_CONF = "/etc/openxs/openxs.conf"

# Tried in this order; the first one that actually has files wins. Plain
# Apache is last since on a Virtualmin/cPanel box it usually only holds
# the server-wide default vhost, not the real per-site logs.
ACCESS_LOG_GLOB_CANDIDATES = [
    "/var/log/virtualmin/*_access_log",
    "/usr/local/apache/domlogs/*",
    "/var/log/apache2/*access*.log",
]


def detect_access_log_glob():
    for pattern in ACCESS_LOG_GLOB_CANDIDATES:
        if glob.glob(pattern):
            return pattern
    return None


def _read_config_value(key, default):
    try:
        with open(OPENXS_CONF, encoding="utf-8", errors="replace") as f:
            for line in f:
                k, sep, v = line.strip().partition("=")
                if sep and k == key and v:
                    return v
    except OSError:
        pass
    return default


def _insert_rule(content, unique_marker, rule_text):
    """Inserts rule_text right after regex.custom.pm's "do not edit
    before this point" marker, unless unique_marker (some substring found
    only inside this specific rule, e.g. its failure-name) is already
    present anywhere in the file - covers both a rule installed by an
    earlier run of this script, and one set up by hand with the exact
    same shape (e.g. the WordPress rule's own origin as a manual
    production deploy, see the Servers repo).
    Returns (new_content, inserted)."""
    if unique_marker in content:
        return content, False
    marker = "# Do not edit before this point"
    idx = content.find(marker)
    if idx < 0:
        print(f"Could not find the expected marker in {CSF_REGEX} - not modified.")
        return content, False
    idx += len(marker)
    return content[:idx] + rule_text + content[idx:], True


def main():
    if not os.path.exists(CSF_CONF):
        print("CSF was not found on this server - nothing to do.")
        return

    apache_log = "/var/log/apache2/error.log" if os.path.exists("/var/log/apache2/error.log") \
        else "/var/log/httpd/error_log"

    with open(CSF_CONF) as f:
        conf = f.read()
    conf, n = re.subn(r'^CUSTOM1_LOG\s*=.*$', f'CUSTOM1_LOG = "{apache_log}"', conf, flags=re.M)
    print(f'Set CUSTOM1_LOG = "{apache_log}" in csf.conf ({n} line(s) updated)')

    access_log_glob = detect_access_log_glob()
    if access_log_glob:
        conf, n = re.subn(r'^CUSTOM2_LOG\s*=.*$', f'CUSTOM2_LOG = "{access_log_glob}"', conf, flags=re.M)
        print(f'Set CUSTOM2_LOG = "{access_log_glob}" in csf.conf ({n} line(s) updated)')
    else:
        print("No known access-log location found (checked Virtualmin/cPanel/plain Apache) - "
              "skipping the WordPress brute-force rule, CUSTOM2_LOG left alone.")

    with open(CSF_CONF, "w") as f:
        f.write(conf)

    with open(CSF_REGEX) as f:
        content = f.read()

    upload_rule = (
        "\n\tif (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ "
        '/\\[client (\\S+?)(?::\\d+)?\\] \\[client \\S+\\] ModSecurity: Access denied.*'
        'rejected by the approver script "\\/opt\\/php-malware-finder\\/inspectfile\\.sh"/)) {\n'
        '\t\treturn ("openxs-scan blocked malicious upload from",$1,"openxs","1","80,443","1","0");\n'
        "\t}\n"
    )
    content, inserted = _insert_rule(content, "openxs-scan", upload_rule)
    print(f"Inserted OpenXS upload-block rule into {CSF_REGEX}" if inserted
          else f"{CSF_REGEX} already has the OpenXS upload-block rule, skipping.")

    if access_log_glob:
        threshold = _read_config_value("WP_BRUTE_THRESHOLD", "30")
        ban_secs = _read_config_value("WP_BRUTE_BAN_SECS", "3600")
        wpbrute_rule = (
            "\n\t# BEGIN wp-bruteforce (Servers repo, 2026-11-08): POSTs to wp-login.php/xmlrpc.php "
            "per IP across all vhost access logs\n"
            "\tif (($globlogs{CUSTOM2_LOG}{$lgfile}) and ($line =~ "
            '/^(\\S+) \\S+ \\S+ \\[[^\\]]+\\] "POST \\/(?:[^" ]*\\/)?(?:xmlrpc|wp-login)\\.php[ ?]/)) {\n'
            f'\t\treturn ("WordPress wp-login/XML-RPC brute force from",$1,"wpbrute","{threshold}",'
            f'"80,443","{ban_secs}","0");\n'
            "\t}\n"
            "\t# END wp-bruteforce\n"
        )
        content, inserted = _insert_rule(content, "wpbrute", wpbrute_rule)
        print(f"Inserted WordPress brute-force rule into {CSF_REGEX} "
              f"(CUSTOM2_LOG={access_log_glob}, threshold={threshold}/h, ban={ban_secs}s)" if inserted
              else f"{CSF_REGEX} already has the WordPress brute-force rule, skipping.")

    with open(CSF_REGEX, "w") as f:
        f.write(content)

    out = subprocess.run(["perl", "-c", CSF_REGEX], capture_output=True, text=True)
    print((out.stdout + out.stderr).strip())
    out = subprocess.run(["csf", "-r"], capture_output=True, text=True)
    print((out.stdout + out.stderr).strip())
    if access_log_glob:
        print("Note: the CUSTOM2_LOG glob is only applied by lfd at its own startup - "
              "a new vhost added later needs 'systemctl restart lfd' to be covered.")


if __name__ == "__main__":
    main()
