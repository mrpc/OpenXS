#!/usr/bin/env python3
"""Mailbox virus scanning - cxs's separate `virusscan` feature (distinct
from `exploitscan`, which the rest of OpenXS replicates). Opt-in
(SCAN_MAILBOXES=1): ClamAV only, not the full YARA ruleset - email
attachments aren't PHP webshells, and cxs itself treated this as its own
separate pass with its own engine.

Real Virtualmin layout, checked on balrog rather than assumed: Maildir
can sit directly under an account (/home/<user>/Maildir) or nested under
a sub-server's own homes dir (/home/<user>/homes/<domain>/Maildir) -
find_maildirs() walks for the directory name either way.
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pmf_scan

MAIL_SUBDIRS = {"cur", "new", "tmp"}  # standard maildir format, including nested IMAP subfolders


def find_maildirs(accounts_dir):
    maildirs = []
    for dirpath, dirnames, _ in os.walk(accounts_dir):
        if "Maildir" in dirnames:
            maildirs.append(os.path.join(dirpath, "Maildir"))
            dirnames.remove("Maildir")  # don't walk into it here - iter_mail_files does that separately
    return maildirs


def iter_mail_files(maildir_paths, changed_hours=None):
    cutoff = time.time() - float(changed_hours) * 3600 if changed_hours else None
    for maildir in maildir_paths:
        for dirpath, _, filenames in os.walk(maildir):
            if os.path.basename(dirpath) not in MAIL_SUBDIRS:
                continue
            for name in filenames:
                path = os.path.join(dirpath, name)
                if cutoff is not None:
                    try:
                        if os.path.getmtime(path) < cutoff:
                            continue
                    except OSError:
                        continue
                yield path


def mail_scan_already_active():
    """Informational only - never blocks SCAN_MAILBOXES from being
    enabled. Checked for real (not assumed) on balrog: milter-greylist
    (anti-spam) and OpenDKIM were active there, neither is an AV milter -
    a server can easily have neither amavisd nor clamav-milter running."""
    for service in ("amavis", "amavisd", "clamav-milter"):
        try:
            out = subprocess.run(["systemctl", "is-active", service],
                                  capture_output=True, text=True, timeout=5).stdout.strip()
            if out == "active":
                return True, f"{service} is active"
        except Exception:
            pass
    try:
        out = subprocess.run(["postconf", "-n"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if ("smtpd_milters" in line or "non_smtpd_milters" in line) and "clam" in line.lower():
                return True, "a ClamAV milter is configured in Postfix"
    except Exception:
        pass
    return False, None


def check(accounts_dir, changed_hours=None):
    """Returns a list of (path, signature) ClamAV findings."""
    maildirs = find_maildirs(accounts_dir)
    files = list(iter_mail_files(maildirs, changed_hours))
    return pmf_scan.clamav_scan(files)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--check-active":
        # Cheap enough to call synchronously from the Settings page - no
        # maildir walk, just a couple of systemctl/postconf calls.
        active, reason = mail_scan_already_active()
        print(f"{int(active)}\t{reason or ''}")
        return
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <accounts-dir> | --check-active", file=sys.stderr)
        sys.exit(1)
    changed_hours = os.environ.get("OPENXS_MAILBOX_RECENT_HOURS")
    findings = check(sys.argv[1], changed_hours)
    active, reason = mail_scan_already_active()
    if active:
        print(f"# Note: mail already appears scanned at delivery time ({reason}) - this check may be redundant here")
    print(f"# Mailbox scan: {len(findings)} infected file(s) found")
    for path, sig in findings:
        print(f"VIRUS\t{path}\t{sig}")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
