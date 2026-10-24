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
