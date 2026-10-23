"""Unit tests for openxs_db.search_findings()/derive_user()/derive_source()
- the unified findings browser query, mirroring cxs's own tabbed
All/Exploits/Virus/Old Versions/... view."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_db as db


def test_derive_user_extracts_account_name():
    assert db.derive_user("/home/someuser/public_html/x.php") == "someuser"


def test_derive_user_none_outside_accounts_dir():
    assert db.derive_user("/tmp/x.php") is None


def test_derive_user_respects_custom_accounts_dir():
    assert db.derive_user("/srv/accounts/bob/x.php", accounts_dir="/srv/accounts") == "bob"


def test_derive_source_migrated():
    assert db.derive_source("migrated from cxs") == "Migrated"
    assert db.derive_source("migrated from cxs (historical logs)") == "Migrated"


def test_derive_source_watch():
    assert db.derive_source("watch:/home/x/shell.php") == "Watch"


def test_derive_source_default_scan():
    assert db.derive_source("/var/www") == "Scan"


def test_search_findings_filters_by_category(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/x", 3, [("/a.php", "Known exploit"), ("/b.php", "Eicar (ClamAV)"), ("/c.php", "Outdated WordPress core: 5.0 (latest: 6.4.2) (oldversion)")])
    rows, count = db.search_findings(category="virus")
    assert count == 1
    assert rows[0][1] == "/b.php"


def test_search_findings_yara_excludes_other_categories(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/x", 3, [("/a.php", "Known exploit"), ("/b.php", "Eicar (ClamAV)"), ("/c.php", "x (maldet)")])
    rows, count = db.search_findings(category="yara")
    assert count == 1
    assert rows[0][1] == "/a.php"


def test_search_findings_no_category_returns_everything(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/x", 2, [("/a.php", "Known exploit"), ("/b.php", "Eicar (ClamAV)")])
    rows, count = db.search_findings()
    assert count == 2


def test_search_findings_search_substring(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/x", 2, [("/home/alice/shell.php", "Known exploit"), ("/home/bob/x.php", "Known exploit")])
    rows, count = db.search_findings(search="alice")
    assert count == 1
    assert rows[0][1] == "/home/alice/shell.php"


def test_search_findings_pagination(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/x", 10, [(f"/f{i}.php", "Known exploit") for i in range(10)])
    rows, count = db.search_findings(limit=4, offset=4)
    assert count == 10
    assert len(rows) == 4


def test_search_findings_includes_date_and_scan_path(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("watch:/home/x/bad.php", 1, [("/home/x/bad.php", "Known exploit")])
    rows, count = db.search_findings()
    fid, file_path, rule_name, qpath, size, started_at, scan_path = rows[0]
    assert scan_path == "watch:/home/x/bad.php"
    assert started_at is not None


def test_search_findings_defaults_to_newest_first(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/x", 1, [("/a.php", "Known exploit")])
    db.record_scan("/x", 1, [("/b.php", "Known exploit")])
    rows, count = db.search_findings()
    assert [r[1] for r in rows] == ["/b.php", "/a.php"]


def test_search_findings_sort_by_date_ascending(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/x", 1, [("/a.php", "Known exploit")])
    db.record_scan("/x", 1, [("/b.php", "Known exploit")])
    rows, count = db.search_findings(sort="date", order="asc")
    assert [r[1] for r in rows] == ["/a.php", "/b.php"]


def test_finding_by_id_returns_row(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/x", 1, [("/a.php", "Known exploit")])
    fid = db.search_findings()[0][0][0]
    row = db.finding_by_id(fid)
    assert row[0] == "/a.php"
    assert row[1] == "Known exploit"


def test_finding_by_id_returns_none_for_missing_id(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    assert db.finding_by_id(999999) is None
