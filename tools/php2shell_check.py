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
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import php_version_check as pvc

DISCLOSURE_DATE = 20261021
FIXED_MIN_PATCH = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}


def is_protected(branch, version):
    major, minor = (int(p) for p in branch.split("."))
    patch = pvc.patch_level(branch, version)
    min_patch = FIXED_MIN_PATCH.get((major, minor))
    if patch is not None and min_patch is not None and patch >= min_patch:
        return True
    snap = pvc.snapshot_date(version)
    if snap is not None and snap >= DISCLOSURE_DATE:
        return True
    return False


def main():
    versions = list(pvc.installed_php_common_versions())
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
