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
