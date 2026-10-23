"""Unit tests for quarantined_files() pagination - added after real-world
use found that rendering every quarantined file in one unpaginated HTML
page (6438 rows, migrated from an existing cxs quarantine) was enough to
hang a browser tab outright."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_db as db


def make_quarantined(tmp_path, n):
    for i in range(n):
        src = tmp_path / f"q{i}.txt"
        src.write_text("x")
        db.import_quarantined_finding(f"/home/x/file{i}.txt", str(src), "rule")


def test_quarantined_files_respects_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    make_quarantined(tmp_path, 10)
    assert len(db.quarantined_files(limit=3)) == 3


def test_quarantined_files_offset_paginates_without_overlap(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    make_quarantined(tmp_path, 10)
    page1 = db.quarantined_files(limit=4, offset=0)
    page2 = db.quarantined_files(limit=4, offset=4)
    ids1 = {r[0] for r in page1}
    ids2 = {r[0] for r in page2}
    assert len(page1) == 4
    assert len(page2) == 4
    assert ids1.isdisjoint(ids2)


def test_quarantined_files_limit_none_returns_everything(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    make_quarantined(tmp_path, 7)
    assert len(db.quarantined_files(limit=None)) == 7


def test_quarantined_files_count_matches_total(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    make_quarantined(tmp_path, 9)
    assert db.quarantined_files_count() == 9
    assert len(db.quarantined_files(limit=5)) == 5  # count isn't capped by the default page size


def make_quarantined_with_dates(tmp_path, dates):
    """dates: list of unix timestamps, oldest/newest in whatever order
    the caller wants - each becomes its own quarantined finding with
    that exact quarantined_at, like a migrated cxs entry would."""
    for i, ts in enumerate(dates):
        src = tmp_path / f"q{i}.txt"
        src.write_text("x")
        db.import_quarantined_finding(f"/home/x/f{i}.txt", str(src), "rule", quarantined_at=ts)


def test_quarantined_files_defaults_to_newest_first(tmp_path, monkeypatch):
    # Insertion order deliberately NOT chronological - a bulk historical
    # import (like migrate_from_cxs.py's) walks files in whatever order
    # the filesystem gives them, not date order, which is exactly the
    # real bug "ORDER BY id DESC" had: id order != date order here.
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    make_quarantined_with_dates(tmp_path, [2000, 3000, 1000])
    rows = db.quarantined_files()
    assert [r[4] for r in rows] == [3000.0, 2000.0, 1000.0]


def test_quarantined_files_sort_by_date_ascending(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    make_quarantined_with_dates(tmp_path, [2000, 3000, 1000])
    rows = db.quarantined_files(sort="date", order="asc")
    assert [r[4] for r in rows] == [1000.0, 2000.0, 3000.0]


def test_quarantined_files_sort_by_size(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    for i, content in enumerate(["xxx", "x", "xx"]):  # f0=3 bytes, f1=1 byte, f2=2 bytes
        src = tmp_path / f"s{i}.txt"
        src.write_text(content)
        db.import_quarantined_finding(f"/home/x/f{i}.txt", str(src), "rule")
    rows = db.quarantined_files(sort="size", order="asc")
    assert [r[1] for r in rows] == ["/home/x/f1.txt", "/home/x/f2.txt", "/home/x/f0.txt"]
