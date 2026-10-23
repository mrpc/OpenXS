"""Unit tests for openxs_logsearch.py - correlating a finding's file with
access logs, and the (never-automatic) IP ban helper."""
import gzip
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_logsearch as ls


def test_url_path_for_strips_account_and_subpath():
    assert ls.url_path_for("/home/someuser/public_html/foo/bar.php") == "/foo/bar.php"


def test_url_path_for_bare_docroot():
    assert ls.url_path_for("/home/someuser/public_html/index.php") == "/index.php"


def test_url_path_for_none_outside_accounts_dir():
    assert ls.url_path_for("/tmp/x.php") is None


def test_url_path_for_respects_custom_subpath():
    assert ls.url_path_for("/srv/bob/www/x.php", accounts_dir="/srv", subpath="www") == "/x.php"


def write_access_log(path, lines):
    with open(path, "wb") as f:
        for line in lines:
            f.write(line.encode() + b"\n")


COMBINED_LINE = (
    '1.2.3.4 - - [23/Oct/2026:12:00:00 +0300] "GET {path} HTTP/1.1" 200 1234 "-" "curl/8.0"'
)


def test_find_access_log_hits_matches_url_path(tmp_path, monkeypatch):
    monkeypatch.setattr(ls, "LOG_DIR", str(tmp_path))
    write_access_log(tmp_path / "site.example.com_access_log", [
        COMBINED_LINE.format(path="/wp-content/uploads/evil.php"),
        COMBINED_LINE.format(path="/index.php"),
    ])
    hits = ls.find_access_log_hits("/home/bob/public_html/wp-content/uploads/evil.php")
    assert len(hits) == 1
    assert hits[0][0] == "1.2.3.4"
    assert "/evil.php" in hits[0][3]


def test_find_access_log_hits_searches_gzipped_logs_too(tmp_path, monkeypatch):
    monkeypatch.setattr(ls, "LOG_DIR", str(tmp_path))
    with gzip.open(tmp_path / "site.example.com_access_log.1.gz", "wb") as f:
        f.write((COMBINED_LINE.format(path="/shell.php") + "\n").encode())
    hits = ls.find_access_log_hits("/home/bob/public_html/shell.php")
    assert len(hits) == 1


def test_find_access_log_hits_returns_empty_for_no_matches(tmp_path, monkeypatch):
    monkeypatch.setattr(ls, "LOG_DIR", str(tmp_path))
    write_access_log(tmp_path / "site.example.com_access_log", [
        COMBINED_LINE.format(path="/unrelated.php"),
    ])
    assert ls.find_access_log_hits("/home/bob/public_html/shell.php") == []


def test_domains_for_user_matches_documentroot(tmp_path):
    (tmp_path / "bob-site.conf").write_text("DocumentRoot /home/bob/public_html\n")
    (tmp_path / "alice-site.conf").write_text("DocumentRoot /home/alice/public_html\n")
    assert ls.domains_for_user("bob", str(tmp_path)) == ["bob-site"]


def test_domains_for_user_no_match_returns_empty(tmp_path):
    (tmp_path / "alice-site.conf").write_text("DocumentRoot /home/alice/public_html\n")
    assert ls.domains_for_user("bob", str(tmp_path)) == []


def test_find_access_log_hits_scopes_to_the_account_own_domain(tmp_path, monkeypatch):
    # Real bug found on balrog: without domain-scoping, a common
    # filename (e.g. index.php) matched hundreds of thousands of
    # unrelated requests across every other site on the server.
    log_dir = tmp_path / "logs"
    vhost_dir = tmp_path / "vhosts"
    log_dir.mkdir()
    vhost_dir.mkdir()
    (vhost_dir / "bob-site.conf").write_text("DocumentRoot /home/bob/public_html\n")
    (vhost_dir / "other-site.conf").write_text("DocumentRoot /home/other/public_html\n")
    write_access_log(log_dir / "bob-site_access_log", [
        COMBINED_LINE.format(path="/index.php"),
    ])
    write_access_log(log_dir / "other-site_access_log", [
        COMBINED_LINE.format(path="/index.php"),  # same filename, unrelated site
    ])
    hits = ls.find_access_log_hits("/home/bob/public_html/index.php",
                                    vhost_dir=str(vhost_dir), log_dir=str(log_dir))
    assert len(hits) == 1
    assert hits[0][4] == "bob-site_access_log"


def test_find_access_log_hits_never_matches_on_bare_basename(tmp_path, monkeypatch):
    # Regression: the old code also searched for the file's bare
    # basename as a fallback, which matched "index.php" (or any common
    # name) anywhere in any log regardless of directory.
    monkeypatch.setattr(ls, "LOG_DIR", str(tmp_path))
    write_access_log(tmp_path / "site.example.com_access_log", [
        COMBINED_LINE.format(path="/completely/different/dir/index.php"),
    ])
    hits = ls.find_access_log_hits("/home/bob/public_html/index.php")
    assert hits == []


def test_summarize_by_ip_counts_and_orders_by_hits():
    # hits is newest-first (as find_access_log_hits returns it): t3 is
    # the most recent occurrence of 1.1.1.1, t1 is its oldest.
    hits = [
        ("1.1.1.1", "t3", "GET", "/x.php", "log1"),
        ("2.2.2.2", "t2", "GET", "/x.php", "log1"),
        ("1.1.1.1", "t1", "GET", "/x.php", "log1"),
    ]
    summary = ls.summarize_by_ip(hits)
    assert list(summary.keys())[0] == "1.1.1.1"
    assert summary["1.1.1.1"]["count"] == 2
    assert summary["2.2.2.2"]["count"] == 1


def test_summarize_by_ip_first_and_last_are_not_swapped():
    # Real bug found via manual testing: "first seen" and "last seen"
    # came out backwards because hits is newest-first, not oldest-first.
    hits = [
        ("1.1.1.1", "newest", "GET", "/x.php", "log1"),
        ("1.1.1.1", "oldest", "GET", "/x.php", "log1"),
    ]
    summary = ls.summarize_by_ip(hits)
    assert summary["1.1.1.1"]["last"] == "newest"
    assert summary["1.1.1.1"]["first"] == "oldest"


def test_ban_ip_rejects_invalid_ip():
    ok, method, msg = ls.ban_ip("'; rm -rf /", "test")
    assert not ok
    assert method is None
    assert "valid" in msg.lower()


def test_ban_ip_prefers_csf_when_available(monkeypatch):
    calls = []

    class FakeResult:
        returncode = 0
        stdout = "IP ... blocked"
        stderr = ""

    monkeypatch.setattr(ls.shutil, "which", lambda name: f"/usr/sbin/{name}" if name == "csf" else None)
    monkeypatch.setattr(ls.subprocess, "run", lambda cmd, **kw: (calls.append(cmd), FakeResult())[1])
    ok, method, msg = ls.ban_ip("1.2.3.4", "flagged file hit")
    assert ok
    assert method == "csf"
    assert calls[0] == ["csf", "-d", "1.2.3.4", "flagged file hit"]


def test_ban_ip_falls_back_to_iptables_when_csf_missing(monkeypatch):
    calls = []

    class FakeResult:
        def __init__(self, returncode):
            self.returncode = returncode
            self.stdout = ""
            self.stderr = ""

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[1] == "-C":
            return FakeResult(1)  # not already blocked
        return FakeResult(0)

    monkeypatch.setattr(ls.shutil, "which", lambda name: f"/sbin/{name}" if name == "iptables" else None)
    monkeypatch.setattr(ls.subprocess, "run", fake_run)
    ok, method, msg = ls.ban_ip("1.2.3.4", "flagged file hit")
    assert ok
    assert method == "iptables"
    assert calls[-1] == ["iptables", "-I", "INPUT", "-s", "1.2.3.4", "-j", "DROP"]


def test_ban_ip_skips_duplicate_iptables_rule(monkeypatch):
    class FakeResult:
        def __init__(self, returncode):
            self.returncode = returncode
            self.stdout = ""
            self.stderr = ""

    monkeypatch.setattr(ls.shutil, "which", lambda name: f"/sbin/{name}" if name == "iptables" else None)
    monkeypatch.setattr(ls.subprocess, "run", lambda cmd, **kw: FakeResult(0))  # -C succeeds: already blocked
    ok, method, msg = ls.ban_ip("1.2.3.4", "flagged file hit")
    assert ok
    assert "already blocked" in msg


def test_ban_ip_reports_no_firewall_available(monkeypatch):
    monkeypatch.setattr(ls.shutil, "which", lambda name: None)
    ok, method, msg = ls.ban_ip("1.2.3.4", "flagged file hit")
    assert not ok
    assert method is None
    assert "neither" in msg.lower()
