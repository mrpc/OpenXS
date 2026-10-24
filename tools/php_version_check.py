"""Shared helpers for "is this server's PHP already protected against
CVE-X" checks, extracted from php2shell_check.py (2026-10-24, the first
such check) so a future CVE-specific gate doesn't need to re-derive how
to enumerate installed PHP versions or compare them against a fixed
version/snapshot-date threshold - it only needs its own small
version_fixed_by()-shaped predicate, same shape as php2shell_check.py's
is_protected().
"""
import re
import subprocess

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


def patch_level(branch, version):
    """The X.Y.Z patch number in version if its X.Y matches branch,
    else None - for comparing against a known-fixed minimum patch."""
    major, minor = (int(p) for p in branch.split("."))
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
    if m and (int(m.group(1)), int(m.group(2))) == (major, minor):
        return int(m.group(3))
    return None


def snapshot_date(version):
    """The embedded YYYYMMDD snapshot/build date in a Debian-style
    version string (e.g. the sury.org EOL-rebuild pattern
    "...+0~20261021.121+debian12~1..."), or None if there isn't one."""
    m = SNAPSHOT_DATE_RE.search(version)
    return int(m.group(1)) if m else None
