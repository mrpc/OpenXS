"""quarantine_file()/restore_file() must handle a symlink finding whose
target is dangling - os.path.exists() follows the link and reports
False (nothing to move), and chmod() follows the link too (would land
on an unrelated target file, not the symlink itself)."""
import os

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_db as db


def test_quarantine_file_moves_a_dangling_symlink(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    link = tmp_path / "current_style"
    link.symlink_to("/no/such/cpanel/theme/path")
    db.record_scan("/x", 1, [(str(link), "symlink")])
    fid = db.search_findings()[0][0][0]

    q_path = db.quarantine_file(fid)

    assert q_path is not None
    assert not os.path.lexists(link)
    assert os.path.islink(q_path)


def test_quarantine_file_does_not_chmod_a_symlinks_target(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    target = tmp_path / "unrelated_target.txt"
    target.write_text("important, unrelated file")
    target.chmod(0o644)
    link = tmp_path / "link"
    link.symlink_to(target)
    db.record_scan("/x", 1, [(str(link), "symlink")])
    fid = db.search_findings()[0][0][0]

    db.quarantine_file(fid)

    import stat
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644


def test_restore_file_restores_a_quarantined_dangling_symlink(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    link = tmp_path / "current_style"
    link.symlink_to("/no/such/cpanel/theme/path")
    db.record_scan("/x", 1, [(str(link), "symlink")])
    fid = db.search_findings()[0][0][0]
    db.quarantine_file(fid)

    assert db.restore_file(fid) is True
    assert os.path.lexists(link)
    assert os.readlink(link) == "/no/such/cpanel/theme/path"
