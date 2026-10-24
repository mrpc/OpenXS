#!/usr/bin/env python3
"""Checks whether every installed PHP version on this server is already
protected against CVE-2026-109618/109619 ("PHP2Shell") - used by
install_modsecurity.sh to decide whether the php2shell.conf ModSecurity
rules are worth installing at all. Minimizes false-positive exposure:
those rules add real (if low) risk for zero benefit on a server where
the vulnerability itself can't be triggered.

Two ways a version can be protected:
- The genuine upstream fix (PHP >= 8.2.35, 8.3.36, 8.4.27, or 8.5.12).
- A supported-elsewhere build repackaged on/after the 2026-10-21
  disclosure - confirmed (OpenXS-ops TIMELINE.md, 2026-10-24) that
  Ondřej Surý's packages.sury.org rebuilds for dead branches (5.6, 7.x,
  8.0, 8.1) force session.upload_progress off at the C level,
  regardless of php.ini, as PHP's own security team's published source
  backport for those branches does. Detected here by the snapshot date
  embedded in the package version string (e.g.
  "...+0~20261021.121+debian12~1...") being on/after the disclosure
  date - this is a heuristic, not a guarantee any given vendor/build
  actually carries the fix, so treat exit 1 as "can't be sure, so
  install the rules" rather than "definitely still vulnerable".
"""
import re
import subprocess
import sys

DISCLOSURE_DATE = 20261021
FIXED_MIN_PATCH = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
SNAPSHOT_DATE_RE = re.compile(r"~(\d{8})\.")


def installed_php_common_versions():
    """Yields (branch_str, version_string) for every installed php*-common
    package, e.g. ("7.4", "1:7.4.33-31+0~20261021.121+debian12~1...")."""
    out = subprocess.run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
                          capture_output=True, text=True).stdout
    for line in out.splitlines():
        pkg, version = line.split("\t", 1)
        m = re.match(r"php(\d+\.\d+)-common$", pkg)
        if m:
            yield m.group(1), version


def is_protected(branch, version):
    major, minor = (int(p) for p in branch.split("."))
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
    if m and (int(m.group(1)), int(m.group(2))) == (major, minor):
        patch = int(m.group(3))
        min_patch = FIXED_MIN_PATCH.get((major, minor))
        if min_patch is not None and patch >= min_patch:
            return True
    snap = SNAPSHOT_DATE_RE.search(version)
    if snap and int(snap.group(1)) >= DISCLOSURE_DATE:
        return True
    return False


def main():
    versions = list(installed_php_common_versions())
    if not versions:
        print("# No php*-common packages found - nothing to check")
        sys.exit(0)
    all_protected = True
    for branch, version in versions:
        protected = is_protected(branch, version)
        print(f"{'PROTECTED' if protected else 'UNPROTECTED'}\tphp{branch}\t{version}")
        if not protected:
            all_protected = False
    sys.exit(0 if all_protected else 1)


if __name__ == "__main__":
    main()
