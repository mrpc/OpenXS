"""Unit tests for openxs_db.new_finding_ids() - only alert on a finding
the first time it's ever seen, not on every scan of an unchanged file."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_db as db


def test_first_scan_everything_is_new(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    scan_id = db.record_scan("/var/www", 2, [("/a.php", "ObfuscatedPhp"), ("/b.php", "DodgyPhp")])
    assert set(db.new_finding_ids(scan_id)) == {("/a.php", "ObfuscatedPhp"), ("/b.php", "DodgyPhp")}


def test_unchanged_file_is_not_new_on_a_later_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    f = tmp_path / "plugin.php"
    f.write_text("same content")
    scan1 = db.record_scan("/var/www", 1, [(str(f), "ObfuscatedPhp")])
    scan2 = db.record_scan("/var/www", 1, [(str(f), "ObfuscatedPhp")])
    assert list(db.new_finding_ids(scan1)) == [(str(f), "ObfuscatedPhp")]
    assert list(db.new_finding_ids(scan2)) == []


def test_file_content_change_counts_as_new_again(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    f = tmp_path / "plugin.php"
    f.write_text("v1")
    scan1 = db.record_scan("/var/www", 1, [(str(f), "ObfuscatedPhp")])
    f.write_text("a longer v2 that changes the file size")
    scan2 = db.record_scan("/var/www", 1, [(str(f), "ObfuscatedPhp")])
    assert list(db.new_finding_ids(scan2)) == [(str(f), "ObfuscatedPhp")]


def test_different_rule_on_same_file_counts_as_new(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    f = tmp_path / "plugin.php"
    f.write_text("same content")
    scan1 = db.record_scan("/var/www", 1, [(str(f), "ObfuscatedPhp")])
    scan2 = db.record_scan("/var/www", 1, [(str(f), "DodgyPhp")])
    assert list(db.new_finding_ids(scan2)) == [(str(f), "DodgyPhp")]
