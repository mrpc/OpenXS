#!/usr/bin/env python3
"""Self-update for OpenXS's own codebase (not the php-malware-finder
ruleset - that's update.cgi's job). Pulls the git clone at OPENXS_SRC
(recorded by install.sh at install time) and re-applies it by re-running
install.sh non-interactively, the same idempotent script a human would
run by hand for an upgrade."""
import os
import subprocess


def _run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def current_commit(src_dir):
    if not src_dir or not os.path.isdir(os.path.join(src_dir, ".git")):
        return None
    rc, out = _run(["git", "rev-parse", "--short", "HEAD"], cwd=src_dir)
    return out.strip() if rc == 0 else None


def check_update(src_dir):
    """Returns (current_commit, latest_commit, commits_behind) without
    changing anything - 'Check for updates' without applying it."""
    cur = current_commit(src_dir)
    if cur is None:
        return None, None, 0
    _run(["git", "fetch", "-q", "origin"], cwd=src_dir)
    rc, out = _run(["git", "rev-parse", "--short", "origin/main"], cwd=src_dir)
    latest = out.strip() if rc == 0 else None
    rc, out = _run(["git", "rev-list", "--count", "HEAD..origin/main"], cwd=src_dir)
    behind = int(out.strip()) if rc == 0 and out.strip().isdigit() else 0
    return cur, latest, behind


if __name__ == "__main__":
    import sys
    src = sys.argv[1] if len(sys.argv) > 1 else "/opt/OpenXS"
    cur, latest, behind = check_update(src)
    print(f"current={cur} latest={latest} behind={behind}")
