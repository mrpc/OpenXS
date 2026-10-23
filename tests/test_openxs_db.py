"""Unit tests for openxs_db.py's duration/load_avg timing columns (the
rest of the module predates this and has no tests yet - out of scope
here)."""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_db as db


def test_record_scan_round_trips_duration_and_load_avg(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/var/www", 10, [], duration=3.5, load_avg=1.25)
    rows = db.recent_scans(limit=1)
    _, _, _, _, _, duration, load_avg = rows[0]
    assert duration == 3.5
    assert load_avg == 1.25


def test_record_scan_defaults_duration_to_none(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/var/www", 10, [])
    rows = db.recent_scans(limit=1)
    assert rows[0][5] is None
    assert rows[0][6] is None


def test_migration_adds_columns_to_pre_existing_db(tmp_path, monkeypatch):
    """A database created before duration/load_avg existed - the ALTER
    TABLE migration must not crash on an old-schema scans table, and
    old rows must read back with NULL for the new columns."""
    db_path = str(tmp_path / "old.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at REAL NOT NULL,
        path TEXT NOT NULL,
        files_scanned INTEGER NOT NULL,
        hits INTEGER NOT NULL
    )""")
    conn.execute("INSERT INTO scans (started_at, path, files_scanned, hits) VALUES (1.0, '/x', 5, 0)")
    conn.commit()
    conn.close()

    monkeypatch.setattr(db, "DB_PATH", db_path)
    rows = db.recent_scans(limit=1)
    assert rows[0][3] == 5  # files_scanned, old data intact
    assert rows[0][5] is None  # duration - column added, old row has no value


def test_migration_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db._connect()
    db._connect()  # running the migration twice must not raise
