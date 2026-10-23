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


def test_fim_info_no_baseline(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENXS_FIM_DB", str(tmp_path / "nope.db"))
    assert st.fim_info() == {"baselined": False}


def test_fim_info_reads_last_results(tmp_path, monkeypatch):
    (tmp_path / "fim.db").write_text("x")
    monkeypatch.setenv("OPENXS_FIM_DB", str(tmp_path / "fim.db"))
    monkeypatch.setattr(st, "PMF_DIR", str(tmp_path))
    (tmp_path / "fim_results.txt").write_text("# Checked against baseline: 1 changed, 0 removed, 0 added\nCHANGED\t/etc/passwd\n")
    info = st.fim_info()
    assert info["baselined"] is True
    assert info["summary"] == "Checked against baseline: 1 changed, 0 removed, 0 added"


def test_version_scan_info_no_results_yet(tmp_path, monkeypatch):
    monkeypatch.setattr(st, "PMF_DIR", str(tmp_path))
    assert st.version_scan_info() == {"ran": False}


def test_version_scan_info_reads_last_results(tmp_path, monkeypatch):
    monkeypatch.setattr(st, "PMF_DIR", str(tmp_path))
    (tmp_path / "version_results.txt").write_text("# WordPress: 2 install(s), 1 outdated\nOUTDATED\t/x\t5.0\t(latest: 6.4.2)\n")
    info = st.version_scan_info()
    assert info["ran"] is True
    assert info["summary"] == "WordPress: 2 install(s), 1 outdated"


def test_apt_security_info_no_results_yet(tmp_path, monkeypatch):
    monkeypatch.setattr(st, "PMF_DIR", str(tmp_path))
    assert st.apt_security_info() == {"ran": False}


def test_apt_security_info_reads_last_results(tmp_path, monkeypatch):
    monkeypatch.setattr(st, "PMF_DIR", str(tmp_path))
    (tmp_path / "apt_security_results.txt").write_text("# Pending apt updates: 9 total, 9 security\nSECURITY\tlibclamav12\t1.4.3\t->\t1.4.6\n")
    info = st.apt_security_info()
    assert info["ran"] is True
    assert info["summary"] == "Pending apt updates: 9 total, 9 security"
