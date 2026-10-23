"""Unit tests for openxs_fim.py."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_fim as fim


def setup_db(tmp_path, monkeypatch):
    monkeypatch.setattr(fim, "DB_PATH", str(tmp_path / "fim.db"))


def test_read_watch_paths_skips_blank_and_comment_lines(tmp_path):
    cfg = tmp_path / "fim_paths"
    cfg.write_text("# a comment\n\n/etc/passwd\n/var/www\n")
    assert fim.read_watch_paths(str(cfg)) == ["/etc/passwd", "/var/www"]


def test_read_watch_paths_missing_file_returns_empty():
    assert fim.read_watch_paths("/no/such/file") == []


def test_iter_files_recurses_directories(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.txt").write_text("1")
    (tmp_path / "sub" / "b.txt").write_text("2")
    found = set(fim.iter_files([str(tmp_path)]))
    assert found == {str(tmp_path / "a.txt"), str(tmp_path / "sub" / "b.txt")}


def test_baseline_then_check_clean(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    f = tmp_path / "watched.txt"
    f.write_text("original")
    assert fim.baseline([str(f)]) == 1
    assert fim.check([str(f)]) == ([], [], [])


def test_check_detects_changed_file(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    f = tmp_path / "watched.txt"
    f.write_text("original")
    fim.baseline([str(f)])
    f.write_text("tampered")
    changed, removed, added = fim.check([str(f)])
    assert changed == [str(f)]
    assert removed == []
    assert added == []


def test_check_detects_removed_file(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    f = tmp_path / "watched.txt"
    f.write_text("original")
    fim.baseline([str(f)])
    f.unlink()
    changed, removed, added = fim.check([str(f)])
    assert removed == [str(f)]


def test_check_detects_added_file_under_watched_dir(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    (tmp_path / "existing.txt").write_text("a")
    fim.baseline([str(tmp_path)])
    (tmp_path / "new.txt").write_text("b")
    changed, removed, added = fim.check([str(tmp_path)])
    assert added == [str(tmp_path / "new.txt")]


def test_rebaselining_clears_previous_drift(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    f = tmp_path / "watched.txt"
    f.write_text("original")
    fim.baseline([str(f)])
    f.write_text("tampered")
    assert fim.check([str(f)]) != ([], [], [])
    fim.baseline([str(f)])
    assert fim.check([str(f)]) == ([], [], [])
