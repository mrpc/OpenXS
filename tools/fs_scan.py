#!/usr/bin/env python3
"""Filesystem-level compromise indicators - cxs's non-PHP-content exploit
checks (SUID files, world-writable dirs, symlinks, sockets, core dumps,
stray Linux/Windows binaries, hidden dirs owned by nobody). These are
permission/filetype signs of compromise, not malicious code content, so
they need stat()/file magic only - no YARA/ClamAV involved.
"""
import sys
import os
import stat
import re

CORE_RE = re.compile(r'^core(\.\d+)?$')

# Panel/OS conventions found live 2026-10-24 to dominate the "symlink"
# finding (9897 of 12526 total fs findings on one server) - not
# account-specific noise, standard practice on every Virtualmin-managed
# domain or stock Apache docroot. Name + exact target pattern (not name
# alone), since a malicious symlink could reuse a familiar-looking name;
# what actually matters is where it points.
KNOWN_BENIGN_SYMLINK_TARGETS = [
    # Virtualmin's per-domain Apache log symlink (logs/access_log,
    # logs/error_log -> the real log file under /var/log/virtualmin/).
    (re.compile(r'^(access|error)_log$'), re.compile(r'^/var/log/virtualmin/')),
    # cPanel/Virtualmin's PHP-version-selector symlink.
    (re.compile(r'^php\d*$'), re.compile(r'^/(usr/)?bin/php[\d.]*$')),
    # A cPanel-to-Virtualmin account migration's leftover theme symlink -
    # dangling (this server has no cPanel installed at all, so the
    # target genuinely doesn't exist), harmless: nothing can ever appear
    # at that target path here for the link to resolve to.
    (re.compile(r'^current_style$'), re.compile(r'^/usr/local/cpanel/')),
]


HOME_ACCOUNT_RE = re.compile(r'^(/home/[^/]+)(/|$)')


def _account_boundary(path, fallback_root):
    """The directory a symlink under path must stay inside of to count
    as "within the same account": /home/<user> when path sits under the
    standard Virtualmin layout (same convention as csf_autoban.py's
    own _username_from_path - an accounts-mode scan walks many
    accounts in one pass, so the overall scan root (e.g. /home) is far
    too broad a boundary, a symlink into a DIFFERENT account under the
    same /home would otherwise wrongly count as "internal"), falling
    back to the overall scan root for a single-path scan."""
    m = HOME_ACCOUNT_RE.match(path)
    if m:
        return os.path.realpath(m.group(1))
    return fallback_root


def _is_benign_symlink(path, fallback_root):
    """True if path (a known symlink) points somewhere that isn't worth
    flagging: another file inside the same account (e.g. a mimetype
    icon pack's "notavailable.png" fallback for filetypes without their
    own icon - a real, common pattern, not a symlink randomly reused
    for dedup elsewhere) or a known panel/OS path. A symlink pointing
    OUTSIDE the account's own tree (another account's home directory,
    /etc/, anywhere unexpected) is the pattern that actually matters
    here and always still gets flagged."""
    try:
        target = os.readlink(path)
    except OSError:
        return False
    abs_target = target if os.path.isabs(target) else os.path.normpath(os.path.join(os.path.dirname(path), target))
    resolved = os.path.realpath(abs_target)
    boundary = _account_boundary(path, fallback_root)
    if resolved == boundary or resolved.startswith(boundary + os.sep):
        return True
    base = os.path.basename(path)
    return any(name_re.match(base) and target_re.match(abs_target)
               for name_re, target_re in KNOWN_BENIGN_SYMLINK_TARGETS)


def magic_kind(path):
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return None
    if head[:4] == b"\x7fELF":
        return "Linux binary or executable file"
    if head[:2] == b"MZ":
        return "Windows binary or executable file"
    return None


def scan(root):
    findings = []
    real_root = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        try:
            st = os.stat(dirpath)
        except OSError:
            continue
        if stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_IWOTH:
            findings.append((dirpath, "world-writable directory"))
        base = os.path.basename(dirpath)
        if base.startswith("."):
            try:
                import pwd
                owner = pwd.getpwuid(st.st_uid).pw_name
            except Exception:
                owner = None
            if owner == "nobody":
                findings.append((dirpath, "hidden directory owned by nobody"))
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                lst = os.lstat(path)
            except OSError:
                continue
            if stat.S_ISLNK(lst.st_mode):
                if not _is_benign_symlink(path, real_root):
                    findings.append((path, "symlink"))
                continue
            if stat.S_ISSOCK(lst.st_mode):
                findings.append((path, "socket"))
                continue
            if not stat.S_ISREG(lst.st_mode):
                continue
            if lst.st_mode & stat.S_ISUID:
                findings.append((path, "SUID file"))
            if CORE_RE.match(name):
                findings.append((path, "core dump file"))
            kind = magic_kind(path)
            if kind:
                findings.append((path, kind))
    return findings


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "/var/www"
    for path, rule in scan(root):
        print(f"{path}\t{rule}")
