"""Unit tests for openxs_db.py's world-writable-directory permission fix/
restore - a directory can't be quarantined the way a file can, so this is
its one-click remediation instead."""
import os
import stat
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_db as db


def _make_finding(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    d = tmp_path / "wtest"
    d.mkdir()
    os.chmod(d, 0o777)
    scan_id = db.record_scan("/home", 1, [(str(d), "world-writable directory")])
    rows = db.findings_for_scan(scan_id)
    fid = rows[0][0]
    return str(d), fid


def test_fix_world_writable_permission_strips_only_the_write_bit(tmp_path, monkeypatch):
    d, fid = _make_finding(tmp_path, monkeypatch)
    new_mode = db.fix_world_writable_permission(fid)
    assert new_mode == 0o775
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o775


def test_fix_world_writable_permission_returns_none_for_missing_path(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    scan_id = db.record_scan("/home", 1, [("/no/such/dir", "world-writable directory")])
    fid = db.findings_for_scan(scan_id)[0][0]
    assert db.fix_world_writable_permission(fid) is None


def test_permission_fix_for_reflects_active_fix(tmp_path, monkeypatch):
    d, fid = _make_finding(tmp_path, monkeypatch)
    assert db.permission_fix_for(fid) is None
    db.fix_world_writable_permission(fid)
    assert db.permission_fix_for(fid) == (0o777, 0o775)


def test_restore_permission_puts_the_original_mode_back(tmp_path, monkeypatch):
    d, fid = _make_finding(tmp_path, monkeypatch)
    db.fix_world_writable_permission(fid)
    assert db.restore_permission(fid)
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o777
    assert db.permission_fix_for(fid) is None  # restored, no longer "active"


def test_restore_permission_false_without_an_active_fix(tmp_path, monkeypatch):
    d, fid = _make_finding(tmp_path, monkeypatch)
    assert db.restore_permission(fid) is False
