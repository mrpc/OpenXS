#!/usr/bin/env python3
"""
Minimal scan-history store for OpenXS (SQLite, stdlib only - no new dependency).
Mirrors the one thing cxs's own cxs.db covered that we didn't have yet: a
persistent record of past scans and their findings, so results aren't lost
the moment the next scan overwrites scan_results.txt.
"""
import os
import sqlite3
import time

DB_PATH = os.environ.get("OPENXS_DB", "/var/lib/openxs/openxs.db")

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
    rule_name TEXT NOT NULL
);
"""


def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    return conn


def record_scan(path, files_scanned, findings):
    """findings: list of (file_path, rule_name) tuples"""
    conn = _connect()
    cur = conn.execute(
        "INSERT INTO scans (started_at, path, files_scanned, hits) VALUES (?, ?, ?, ?)",
        (time.time(), path, files_scanned, len(findings)),
    )
    scan_id = cur.lastrowid
    conn.executemany(
        "INSERT INTO findings (scan_id, file_path, rule_name) VALUES (?, ?, ?)",
        [(scan_id, f, r) for f, r in findings],
    )
    conn.commit()
    conn.close()
    return scan_id


def recent_scans(limit=50):
    conn = _connect()
    rows = conn.execute(
        "SELECT id, started_at, path, files_scanned, hits FROM scans ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def findings_for_scan(scan_id):
    conn = _connect()
    rows = conn.execute(
        "SELECT file_path, rule_name FROM findings WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    conn.close()
    return rows
