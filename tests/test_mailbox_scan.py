"""Unit tests for mailbox_scan.py."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import mailbox_scan as ms


def make_maildir(base, *, cur=(), new=()):
    maildir = base / "Maildir"
    for sub, names in (("cur", cur), ("new", new), ("tmp", ())):
        (maildir / sub).mkdir(parents=True, exist_ok=True)
        for name in names:
            (maildir / sub / name).write_text("From: test\n\nbody")
    return maildir


def test_find_maildirs_direct_under_account(tmp_path):
    make_maildir(tmp_path / "user1")
    found = ms.find_maildirs(str(tmp_path))
    assert found == [str(tmp_path / "user1" / "Maildir")]


def test_find_maildirs_nested_under_homes_subserver(tmp_path):
    make_maildir(tmp_path / "user1" / "homes" / "example.com")
    found = ms.find_maildirs(str(tmp_path))
    assert found == [str(tmp_path / "user1" / "homes" / "example.com" / "Maildir")]


def test_find_maildirs_multiple_accounts(tmp_path):
    make_maildir(tmp_path / "user1")
    make_maildir(tmp_path / "user2")
    assert len(ms.find_maildirs(str(tmp_path))) == 2


def test_iter_mail_files_only_cur_new_tmp(tmp_path):
    maildir = make_maildir(tmp_path / "user1", cur=("msg1",), new=("msg2",))
    (maildir / "other_junk").mkdir()  # not a real maildir subdir - should be skipped
    (maildir / "other_junk" / "notmail.txt").write_text("x")
    files = set(ms.iter_mail_files([str(maildir)]))
    assert files == {str(maildir / "cur" / "msg1"), str(maildir / "new" / "msg2")}


def test_iter_mail_files_finds_nested_imap_subfolder_mail(tmp_path):
    maildir = make_maildir(tmp_path / "user1", cur=("msg1",))
    (maildir / ".Spam" / "cur").mkdir(parents=True)
    (maildir / ".Spam" / "cur" / "spam_msg").write_text("spam")
    files = set(ms.iter_mail_files([str(maildir)]))
    assert str(maildir / ".Spam" / "cur" / "spam_msg") in files


def test_iter_mail_files_changed_hours_filter(tmp_path):
    maildir = make_maildir(tmp_path / "user1", cur=("old_msg",))
    old_path = maildir / "cur" / "old_msg"
    old_time = time.time() - 48 * 3600
    os.utime(old_path, (old_time, old_time))
    files = list(ms.iter_mail_files([str(maildir)], changed_hours="24"))
    assert files == []


def test_check_delegates_to_clamav_scan(tmp_path, monkeypatch):
    maildir = make_maildir(tmp_path / "user1", cur=("msg1",))
    captured = {}
    def fake_clamav_scan(files):
        captured["files"] = files
        return [(files[0], "Eicar-Test-Signature")]
    monkeypatch.setattr(ms.pmf_scan, "clamav_scan", fake_clamav_scan)
    results = ms.check(str(tmp_path))
    assert results == [(str(maildir / "cur" / "msg1"), "Eicar-Test-Signature")]


def test_mail_scan_already_active_false_when_nothing_running(monkeypatch):
    class FakeResult:
        stdout = "inactive"
    monkeypatch.setattr(ms.subprocess, "run", lambda *a, **k: FakeResult())
    active, reason = ms.mail_scan_already_active()
    assert active is False
    assert reason is None


def test_mail_scan_already_active_detects_amavis(monkeypatch):
    def fake_run(args, **kwargs):
        class R:
            stdout = "active" if args[2] == "amavis" else "inactive"
        return R()
    monkeypatch.setattr(ms.subprocess, "run", fake_run)
    active, reason = ms.mail_scan_already_active()
    assert active is True
    assert "amavis" in reason
