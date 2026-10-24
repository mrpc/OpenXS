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


def test_detects_symlink_pointing_outside_the_scanned_root(tmp_path):
    # Outside the scanned root entirely - the pattern that actually
    # matters (reading/writing somewhere it shouldn't).
    outside = tmp_path.parent / f"outside-target-{tmp_path.name}.txt"
    outside.write_text("x")
    try:
        scan_root = tmp_path / "site"
        scan_root.mkdir()
        link = scan_root / "link"
        link.symlink_to(outside)
        findings = findings_dict(scan_root)
        assert findings.get(str(link)) == "symlink"
    finally:
        outside.unlink()


def test_symlink_within_the_same_scanned_root_is_not_flagged(tmp_path):
    # e.g. a mimetype icon pack's "notavailable.png" fallback - points
    # to another file in the same site, not outside it.
    target = tmp_path / "target.txt"
    target.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(target)
    findings = findings_dict(tmp_path)
    assert str(link) not in findings


def test_symlink_within_same_home_account_not_flagged_even_if_outside_scan_root(tmp_path, monkeypatch):
    # Accounts-mode scan: root is /home itself (many accounts in one
    # pass), so the per-account boundary (/home/<user>) must be used,
    # not the overall /home root - this is the case a too-broad
    # boundary would get wrong (silently "contain" another account).
    home = tmp_path / "home"
    account = home / "someuser"
    account.mkdir(parents=True)
    target = account / "target.txt"
    target.write_text("x")
    link = account / "public_html" / "link"
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    monkeypatch.setattr(fs_scan, "HOME_ACCOUNT_RE", __import__("re").compile(r'^(' + str(home) + r'/[^/]+)(/|$)'))
    findings = findings_dict(home)
    assert str(link) not in findings


def test_symlink_into_a_different_home_account_is_still_flagged(tmp_path, monkeypatch):
    home = tmp_path / "home"
    account_a = home / "usera"
    account_b = home / "userb"
    account_a.mkdir(parents=True)
    account_b.mkdir(parents=True)
    target = account_b / "secret.txt"
    target.write_text("x")
    link = account_a / "public_html" / "link"
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    monkeypatch.setattr(fs_scan, "HOME_ACCOUNT_RE", __import__("re").compile(r'^(' + str(home) + r'/[^/]+)(/|$)'))
    findings = findings_dict(home)
    assert findings.get(str(link)) == "symlink"


def test_known_virtualmin_access_log_symlink_not_flagged(tmp_path, monkeypatch):
    varlog = tmp_path / "var_log_virtualmin"
    varlog.mkdir()
    real_log = varlog / "example.com_access_log"
    real_log.write_text("log line")
    scan_root = tmp_path / "site"
    logs_dir = scan_root / "logs"
    logs_dir.mkdir(parents=True)
    link = logs_dir / "access_log"
    link.symlink_to(real_log)
    monkeypatch.setattr(fs_scan, "KNOWN_BENIGN_SYMLINK_TARGETS",
                         [(__import__("re").compile(r'^(access|error)_log$'),
                           __import__("re").compile(r'^' + str(varlog) + r'/'))])
    findings = findings_dict(scan_root)
    assert str(link) not in findings


def test_similarly_named_symlink_to_an_unexpected_target_is_still_flagged(tmp_path):
    # Same basename ("access_log") as the known-benign Virtualmin
    # pattern, but pointing somewhere that isn't /var/log/virtualmin/ -
    # the name alone must never be enough to suppress a finding.
    elsewhere = tmp_path.parent / f"elsewhere-{tmp_path.name}.txt"
    elsewhere.write_text("not a real virtualmin log")
    try:
        scan_root = tmp_path / "site"
        logs_dir = scan_root / "logs"
        logs_dir.mkdir(parents=True)
        link = logs_dir / "access_log"
        link.symlink_to(elsewhere)
        findings = findings_dict(scan_root)
        assert findings.get(str(link)) == "symlink"
    finally:
        elsewhere.unlink()


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
