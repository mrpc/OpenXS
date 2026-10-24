"""Unit tests for openxs_db.py's false_positive_reports table."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_db as db


def test_record_false_positive_round_trips(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_false_positive("modsec", "/el/account/googleauth", "930120", action_taken="rule 930120 excluded (ARGS)")
    conn = db._connect()
    row = conn.execute("SELECT source, path, detail, action_taken FROM false_positive_reports").fetchone()
    assert row == ("modsec", "/el/account/googleauth", "930120", "rule 930120 excluded (ARGS)")


def test_record_false_positive_action_taken_defaults_to_none(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_false_positive("oldversion", "/home/site/composer.lock", "acme/pkg")
    conn = db._connect()
    row = conn.execute("SELECT action_taken FROM false_positive_reports").fetchone()
    assert row[0] is None


def test_false_positive_daily_stats_filled_buckets_by_day(tmp_path, monkeypatch):
    import time
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_false_positive("modsec", "/x", "930120")
    db.record_false_positive("finding", "/y", "ObfuscatedPhp")
    result = db.false_positive_daily_stats_filled(days=7)
    assert len(result) == 7
    today = result[-1]
    assert today[0] == time.strftime("%Y-%m-%d")
    assert today[1] == 2


def test_false_positive_daily_stats_filled_zero_fills_empty_days(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    result = db.false_positive_daily_stats_filled(days=5)
    assert len(result) == 5
    assert all(count == 0 for _date, count in result)


def test_false_positive_counts_by_source(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_false_positive("modsec", "/x", "930120")
    db.record_false_positive("modsec", "/x2", "941310")
    db.record_false_positive("finding", "/y", "ObfuscatedPhp")
    assert db.false_positive_counts_by_source() == {"modsec": 2, "finding": 1}
