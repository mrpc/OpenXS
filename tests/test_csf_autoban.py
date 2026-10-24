import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import csf_autoban as autoban


SAMPLE_POST_LINE = '1.2.3.4 - - [24/Oct/2026:20:00:00] "POST /upload.php HTTP/1.1" 200 1234 "-" "UA"'


def test_username_from_path():
    assert autoban._username_from_path("/home/geekdom/public_html/x.php") == "geekdom"
    assert autoban._username_from_path("/var/www/x.php") is None


def test_find_unambiguous_recent_uploader_ip_single_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(autoban, "_domain_for_user", lambda u: "example.com")
    log_dir = tmp_path
    (log_dir / "example.com_access_log").write_text(SAMPLE_POST_LINE + "\n")
    now = time.mktime(time.strptime("24/Oct/2026:20:00:05", "%d/%b/%Y:%H:%M:%S"))
    monkeypatch.setattr(autoban.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"stdout": SAMPLE_POST_LINE + "\n"})())

    ip = autoban.find_unambiguous_recent_uploader_ip(
        "/home/geekdom/public_html/x.php", window_seconds=15, now=now, log_dir=str(log_dir))
    assert ip == "1.2.3.4"


def test_find_unambiguous_recent_uploader_ip_no_match_no_username(tmp_path, monkeypatch):
    assert autoban.find_unambiguous_recent_uploader_ip("/var/www/x.php") is None


def test_find_unambiguous_recent_uploader_ip_multiple_candidates_is_ambiguous(monkeypatch):
    monkeypatch.setattr(autoban, "_domain_for_user", lambda u: "example.com")
    line2 = SAMPLE_POST_LINE.replace("1.2.3.4", "5.6.7.8")
    monkeypatch.setattr(autoban.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"stdout": SAMPLE_POST_LINE + "\n" + line2 + "\n"})())
    monkeypatch.setattr(autoban.os.path, "isfile", lambda p: True)
    now = time.mktime(time.strptime("24/Oct/2026:20:00:05", "%d/%b/%Y:%H:%M:%S"))

    ip = autoban.find_unambiguous_recent_uploader_ip("/home/geekdom/public_html/x.php", now=now)
    assert ip is None


def test_find_unambiguous_recent_uploader_ip_outside_window_is_ignored(monkeypatch):
    monkeypatch.setattr(autoban, "_domain_for_user", lambda u: "example.com")
    monkeypatch.setattr(autoban.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"stdout": SAMPLE_POST_LINE + "\n"})())
    monkeypatch.setattr(autoban.os.path, "isfile", lambda p: True)
    far_future = time.mktime(time.strptime("24/Oct/2026:20:00:05", "%d/%b/%Y:%H:%M:%S")) + 3600

    ip = autoban.find_unambiguous_recent_uploader_ip("/home/geekdom/public_html/x.php", now=far_future)
    assert ip is None


def test_find_unambiguous_recent_uploader_ip_refuses_cloudflare_ip(monkeypatch):
    monkeypatch.setattr(autoban, "_domain_for_user", lambda u: "example.com")
    cf_line = SAMPLE_POST_LINE.replace("1.2.3.4", "162.158.1.1")
    monkeypatch.setattr(autoban.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"stdout": cf_line + "\n"})())
    monkeypatch.setattr(autoban.os.path, "isfile", lambda p: True)
    now = time.mktime(time.strptime("24/Oct/2026:20:00:05", "%d/%b/%Y:%H:%M:%S"))

    ip = autoban.find_unambiguous_recent_uploader_ip("/home/geekdom/public_html/x.php", now=now)
    assert ip is None


def test_ban_calls_csf_temp_deny(monkeypatch):
    calls = []

    class FakeResult:
        returncode = 0

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return FakeResult()

    monkeypatch.setattr(autoban.subprocess, "run", fake_run)
    assert autoban.ban("1.2.3.4", "test reason", ttl="3d") is True
    assert calls == [["csf", "-td", "1.2.3.4", "3d", "test reason"]]


def test_ban_returns_false_on_failure(monkeypatch):
    class FakeResult:
        returncode = 1

    monkeypatch.setattr(autoban.subprocess, "run", lambda *a, **kw: FakeResult())
    assert autoban.ban("1.2.3.4", "reason") is False
