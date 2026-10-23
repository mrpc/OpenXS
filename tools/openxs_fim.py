#!/usr/bin/env python3
"""File Integrity Monitoring: hashes a configured list of important files/
directories into a small SQLite baseline, then reports drift against it -
something cxs never did and OpenXS didn't have either (the existing
check_whitelist_drift.py is a different, narrower thing: it only tracks
our own already-whitelisted exploit-scan entries, not arbitrary files like
/etc/passwd, web server configs, or framework core files).

Report-only: `check` never touches the baseline. Accepting a legitimate
change is a deliberate `baseline` re-run, same philosophy as
check_whitelist_drift.py's own "re-whitelisting is a reviewed step."
"""
import hashlib
import os
import sqlite3
import sys
import time

DB_PATH = os.environ.get("OPENXS_FIM_DB", "/var/lib/openxs/fim.db")
WATCH_FILE = os.environ.get("OPENXS_FIM_PATHS", "/etc/openxs/fim_paths")

SCHEMA = """
CREATE TABLE IF NOT EXISTS fim_baseline (
    path TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime REAL NOT NULL,
    recorded_at REAL NOT NULL
);
"""


def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    return conn


def read_watch_paths(config_path=None):
    """One file-or-directory path per line; blank/# lines skipped - same
    convention as /etc/openxs/ignore and the other config files."""
    config_path = config_path or WATCH_FILE
    paths = []
    try:
        with open(config_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                paths.append(line)
    except OSError:
        pass
    return paths


def iter_files(watch_paths):
    for p in watch_paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for name in files:
                    yield os.path.join(root, name)
        elif os.path.isfile(p):
            yield p


def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def baseline(watch_paths):
    """(Re-)records the current state of every file under watch_paths as
    the new baseline. Returns the number of files recorded."""
    conn = _connect()
    count = 0
    now = time.time()
    for path in iter_files(watch_paths):
        try:
            st = os.stat(path)
            digest = hash_file(path)
        except OSError:
            continue
        conn.execute(
            "INSERT INTO fim_baseline (path, sha256, size, mtime, recorded_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256, size=excluded.size, "
            "mtime=excluded.mtime, recorded_at=excluded.recorded_at",
            (path, digest, st.st_size, st.st_mtime, now),
        )
        count += 1
    conn.commit()
    conn.close()
    return count


def check(watch_paths):
    """Returns (changed, removed, added) path lists - never writes to the
    baseline itself."""
    conn = _connect()
    baselined = dict(conn.execute("SELECT path, sha256 FROM fim_baseline").fetchall())
    conn.close()

    seen = set()
    changed, added = [], []
    for path in iter_files(watch_paths):
        seen.add(path)
        try:
            digest = hash_file(path)
        except OSError:
            continue
        if path not in baselined:
            added.append(path)
        elif digest != baselined[path]:
            changed.append(path)

    removed = [p for p in baselined if p not in seen]
    return sorted(changed), sorted(removed), sorted(added)


def main():
    watch_paths = read_watch_paths()
    if not watch_paths:
        print(f"# No paths configured in {WATCH_FILE} - nothing to do.", file=sys.stderr)
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "baseline":
        count = baseline(watch_paths)
        print(f"# Baselined {count} file(s) from {len(watch_paths)} configured path(s)")
        return

    changed, removed, added = check(watch_paths)
    print(f"# Checked against baseline: {len(changed)} changed, {len(removed)} removed, {len(added)} added")
    for p in changed:
        print(f"CHANGED\t{p}")
    for p in removed:
        print(f"REMOVED\t{p}")
    for p in added:
        print(f"ADDED\t{p}")
    sys.exit(1 if (changed or removed or added) else 0)


if __name__ == "__main__":
    main()
