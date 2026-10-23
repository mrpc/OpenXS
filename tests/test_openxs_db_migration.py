"""Unit tests for openxs_db.import_quarantined_finding() (used by
migrate_from_cxs.py)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_db as db


def test_import_quarantined_finding_moves_file_and_chmods_000(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    src = tmp_path / "cxs_quarantine" / "oldfile.txt.12345"
    src.parent.mkdir()
    src.write_text("malicious content")

    q_path = db.import_quarantined_finding("/home/user/oldfile.txt", str(src), "Known exploit = [Fingerprint Match]")

    assert not src.exists()  # moved, not copied
    assert os.path.exists(q_path)
    assert oct(os.stat(q_path).st_mode)[-3:] == "000"


def test_import_quarantined_finding_shows_up_in_quarantined_files(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    src = tmp_path / "cxs_quarantine" / "oldfile.txt.12345"
    src.parent.mkdir()
    src.write_text("x")

    db.import_quarantined_finding("/home/user/oldfile.txt", str(src), "Known exploit")
    rows = db.quarantined_files()
    assert len(rows) == 1
    assert rows[0][1] == "/home/user/oldfile.txt"
    assert rows[0][2] == "Known exploit"


def test_import_quarantined_finding_is_restorable(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    src = tmp_path / "cxs_quarantine" / "oldfile.txt.12345"
    src.parent.mkdir()
    src.write_text("x")
    original_path = str(tmp_path / "restored_here" / "oldfile.txt")

    db.import_quarantined_finding(original_path, str(src), "Known exploit")
    finding_id = db.quarantined_files()[0][0]
    assert db.restore_file(finding_id) is True
    assert os.path.exists(original_path)
