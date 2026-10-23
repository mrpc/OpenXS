"""Unit tests for openxs_status.py's own parsing logic (the rest is thin
subprocess/os wrappers not worth mocking)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_status as st


def test_last_scan_info_no_log(tmp_path, monkeypatch):
    monkeypatch.setattr(st, "PMF_DIR", str(tmp_path))
    assert st.last_scan_info() == {"ran": False}


def test_last_scan_info_parses_last_summary_line(tmp_path, monkeypatch):
    monkeypatch.setattr(st, "PMF_DIR", str(tmp_path))
    log = tmp_path / "scan.log"
    log.write_text(
        "# Scanned 10 file(s), 0 flagged\n"
        "some noise\n"
        "# Scanned 12 file(s), 1 flagged (YARA)\n"
    )
    info = st.last_scan_info()
    assert info["ran"] is True
    assert info["summary"] == "Scanned 12 file(s), 1 flagged (YARA)"


def test_quarantine_count_counts_only_files(tmp_path, monkeypatch):
    monkeypatch.setattr(st, "QUARANTINE_DIR", str(tmp_path))
    (tmp_path / "a").write_text("x")
    (tmp_path / "b").write_text("x")
    (tmp_path / "subdir").mkdir()
    assert st.quarantine_count() == 2


def test_quarantine_count_missing_dir_returns_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(st, "QUARANTINE_DIR", str(tmp_path / "nope"))
    assert st.quarantine_count() == 0
