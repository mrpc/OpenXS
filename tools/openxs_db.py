#!/usr/bin/env python3
"""
Minimal scan-history + quarantine store for OpenXS (SQLite, stdlib only - no
new dependency). Mirrors the two things cxs's own cxs.db / quarantine dir
covered that we didn't have yet.
"""
import os
import sqlite3
import time

DB_PATH = os.environ.get("OPENXS_DB", "/var/lib/openxs/openxs.db")
QUARANTINE_DIR = os.environ.get("OPENXS_QUARANTINE", "/var/lib/openxs/quarantine")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    path TEXT NOT NULL,
    files_scanned INTEGER NOT NULL,
    hits INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    file_path TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    quarantine_path TEXT
);
"""


def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    # Added after the initial release - ALTER TABLE, not a CREATE TABLE
    # clause, since that only applies to a table that doesn't exist yet
    # and an existing openxs.db already has the old `scans` schema.
    for column in ("duration REAL", "load_avg REAL"):
        try:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {column}")
        except sqlite3.OperationalError:
            pass  # already added in a previous run
    return conn


def record_scan(path, files_scanned, findings, duration=None, load_avg=None):
    """findings: list of (file_path, rule_name) tuples"""
    conn = _connect()
    cur = conn.execute(
        "INSERT INTO scans (started_at, path, files_scanned, hits, duration, load_avg) VALUES (?, ?, ?, ?, ?, ?)",
        (time.time(), path, files_scanned, len(findings), duration, load_avg),
    )
    scan_id = cur.lastrowid
    conn.executemany(
        "INSERT INTO findings (scan_id, file_path, rule_name) VALUES (?, ?, ?)",
        [(scan_id, f, r) for f, r in findings],
    )
    conn.commit()
    conn.close()
    return scan_id


def quarantine_file(finding_id):
    """Moves a finding's file into the quarantine dir and records the new
    path. Returns the quarantine path, or None if the file no longer exists
    (already moved/deleted) or was already quarantined."""
    conn = _connect()
    row = conn.execute(
        "SELECT file_path, quarantine_path FROM findings WHERE id = ?", (finding_id,)
    ).fetchone()
    if not row:
        conn.close()
        return None
    file_path, existing_q = row
    if existing_q:
        conn.close()
        return existing_q
    if not os.path.exists(file_path):
        conn.close()
        return None

    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    safe_name = file_path.replace("/", "_").lstrip("_")
    q_path = os.path.join(QUARANTINE_DIR, f"{finding_id}_{safe_name}")
    os.rename(file_path, q_path)
    os.chmod(q_path, 0o000)

    conn.execute("UPDATE findings SET quarantine_path = ? WHERE id = ?", (q_path, finding_id))
    conn.commit()
    conn.close()
    return q_path


def restore_file(finding_id):
    """Moves a quarantined file back to its original location."""
    conn = _connect()
    row = conn.execute(
        "SELECT file_path, quarantine_path FROM findings WHERE id = ?", (finding_id,)
    ).fetchone()
    if not row or not row[1]:
        conn.close()
        return False
    file_path, q_path = row
    if not os.path.exists(q_path):
        conn.close()
        return False
    os.chmod(q_path, 0o644)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    os.rename(q_path, file_path)
    conn.execute("UPDATE findings SET quarantine_path = NULL WHERE id = ?", (finding_id,))
    conn.commit()
    conn.close()
    return True


def delete_quarantined(finding_id):
    """Permanently deletes a quarantined file."""
    conn = _connect()
    row = conn.execute(
        "SELECT quarantine_path FROM findings WHERE id = ?", (finding_id,)
    ).fetchone()
    if not row or not row[0]:
        conn.close()
        return False
    q_path = row[0]
    if os.path.exists(q_path):
        os.remove(q_path)
    conn.execute("UPDATE findings SET quarantine_path = ? WHERE id = ?", ("__deleted__", finding_id))
    conn.commit()
    conn.close()
    return True


def recent_scans(limit=50):
    conn = _connect()
    rows = conn.execute(
        "SELECT id, started_at, path, files_scanned, hits, duration, load_avg FROM scans ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def findings_for_scan(scan_id):
    conn = _connect()
    rows = conn.execute(
        "SELECT id, file_path, rule_name, quarantine_path FROM findings WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()
    conn.close()
    return rows


def quarantined_files():
    conn = _connect()
    rows = conn.execute(
        "SELECT id, file_path, rule_name, quarantine_path FROM findings "
        "WHERE quarantine_path IS NOT NULL AND quarantine_path != '__deleted__' "
        "ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return rows
