"""Unit tests for fs_scan.py - filesystem-level compromise indicators."""
import os
import stat
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import fs_scan


def findings_dict(root):
    return dict(fs_scan.scan(str(root)))


def test_detects_world_writable_directory(tmp_path):
    d = tmp_path / "wtest"
    d.mkdir()
    d.chmod(0o777)
    findings = findings_dict(tmp_path)
    assert findings.get(str(d)) == "world-writable directory"


def test_detects_symlink(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(target)
    findings = findings_dict(tmp_path)
    assert findings.get(str(link)) == "symlink"


def test_detects_core_dump_file(tmp_path):
    core = tmp_path / "core.1234"
    core.write_text("")
    findings = findings_dict(tmp_path)
    assert findings.get(str(core)) == "core dump file"
    core2 = tmp_path / "core"
    core2.write_text("")
    findings2 = findings_dict(tmp_path)
    assert findings2.get(str(core2)) == "core dump file"


def test_detects_suid_file(tmp_path):
    f = tmp_path / "suid_bin"
    f.write_text("x")
    f.chmod(0o4755)
    findings = findings_dict(tmp_path)
    assert findings.get(str(f)) == "SUID file"


def test_ignores_ordinary_file(tmp_path):
    f = tmp_path / "normal.php"
    f.write_text("<?php ?>")
    findings = findings_dict(tmp_path)
    assert str(f) not in findings


def test_magic_kind_detects_elf_header(tmp_path):
    f = tmp_path / "elfish"
    f.write_bytes(b"\x7fELF" + b"\x00" * 10)
    assert fs_scan.magic_kind(str(f)) == "Linux binary or executable file"


def test_magic_kind_detects_pe_header(tmp_path):
    f = tmp_path / "winish"
    f.write_bytes(b"MZ" + b"\x00" * 10)
    assert fs_scan.magic_kind(str(f)) == "Windows binary or executable file"


def test_magic_kind_plain_file_returns_none(tmp_path):
    f = tmp_path / "plain.txt"
    f.write_text("just text")
    assert fs_scan.magic_kind(str(f)) is None


def test_magic_kind_missing_file_returns_none():
    assert fs_scan.magic_kind("/no/such/file") is None
