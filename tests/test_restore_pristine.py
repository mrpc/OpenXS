import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import restore_pristine as rp
import openxs_db as db


def test_repair_file_not_found(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    ok, err = rp.repair_file(999999)
    assert ok is False
    assert "not found" in err


def test_repair_file_already_quarantined(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    f = tmp_path / "a.php"
    f.write_bytes(b"backdoored")
    scan_id = db.record_scan("/x", 1, [(str(f), "ObfuscatedPhp")])
    fid = db.findings_for_scan(scan_id)[0][0]
    db.quarantine_file(fid)
    ok, err = rp.repair_file(fid)
    assert ok is False
    assert "already quarantined" in err


def test_repair_file_vanished(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    f = tmp_path / "a.php"
    f.write_bytes(b"backdoored")
    scan_id = db.record_scan("/x", 1, [(str(f), "ObfuscatedPhp")])
    fid = db.findings_for_scan(scan_id)[0][0]
    f.unlink()
    ok, err = rp.repair_file(fid)
    assert ok is False
    assert "no longer exists" in err


def test_repair_file_unresolvable_content(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    f = tmp_path / "a.php"  # not under any recognized platform/package root
    f.write_bytes(b"whatever")
    scan_id = db.record_scan("/x", 1, [(str(f), "ObfuscatedPhp")])
    fid = db.findings_for_scan(scan_id)[0][0]
    monkeypatch.setattr(rp, "_fetch_pristine_content", lambda path: None)
    ok, err = rp.repair_file(fid)
    assert ok is False
    assert "could not determine" in err
    assert f.read_bytes() == b"whatever"  # untouched - never quarantined on a dry hole


def test_repair_file_success_backs_up_and_restores_permissions(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    f = tmp_path / "a.php"
    f.write_bytes(b"backdoored content")
    os.chmod(f, 0o640)
    scan_id = db.record_scan("/x", 1, [(str(f), "ObfuscatedPhp")])
    fid = db.findings_for_scan(scan_id)[0][0]

    monkeypatch.setattr(rp, "_fetch_pristine_content", lambda path: b"<?php // stock content")
    ok, err = rp.repair_file(fid)
    assert ok is True
    assert err is None
    assert f.read_bytes() == b"<?php // stock content"
    assert (os.stat(f).st_mode & 0o777) == 0o640  # same mode as the file that got replaced

    row = db.finding_by_id(fid)
    quarantine_path = row[2]
    assert quarantine_path and os.path.lexists(quarantine_path)
    os.chmod(quarantine_path, 0o600)  # quarantine_file() locks it to 0o000 - reopen for the check
    with open(quarantine_path, "rb") as qf:
        assert qf.read() == b"backdoored content"  # the ORIGINAL content, safely backed up
