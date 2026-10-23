"""Unit tests for openxs_db's daily_stats aggregate table (mirrors cxs's
own cxsscan_counters/cxswatch_counters design - incrementally updated,
not recomputed via GROUP BY at read time)."""
import datetime
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_db as db


def test_record_scan_increments_todays_daily_stats(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/var/www", 10, [("/x", "rule")], duration=2.5)
    rows = db.daily_stats(days=1)
    assert len(rows) == 1
    date, scan_count, files_scanned, hits, quarantined, avg_duration = rows[0]
    assert date == time.strftime("%Y-%m-%d", time.gmtime())
    assert scan_count == 1
    assert files_scanned == 10
    assert hits == 1
    assert quarantined == 0
    assert avg_duration == 2.5


def test_record_scan_accumulates_across_multiple_scans_same_day(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/var/www", 10, [], duration=2.0)
    db.record_scan("/var/www", 20, [("/x", "r")], duration=4.0)
    rows = db.daily_stats(days=1)
    date, scan_count, files_scanned, hits, quarantined, avg_duration = rows[0]
    assert scan_count == 2
    assert files_scanned == 30
    assert hits == 1
    assert avg_duration == 3.0  # (2.0 + 4.0) / 2


def test_record_scan_without_duration_does_not_skew_average(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/var/www", 10, [])  # no duration
    db.record_scan("/var/www", 10, [], duration=5.0)
    rows = db.daily_stats(days=1)
    assert rows[0][5] == 5.0  # average of just the one scan that had a duration, not averaged with 0


def test_quarantine_file_increments_quarantined_counter(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    f = tmp_path / "bad.php"
    f.write_text("x")
    scan_id = db.record_scan(str(tmp_path), 1, [(str(f), "rule")])
    finding_id = db.findings_for_scan(scan_id)[0][0]
    db.quarantine_file(finding_id)
    rows = db.daily_stats(days=1)
    assert rows[0][4] == 1  # quarantined


def test_import_quarantined_finding_credits_its_own_historical_day(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    src = tmp_path / "old.txt"
    src.write_text("x")
    old_time = time.time() - 10 * 86400  # 10 days ago
    db.import_quarantined_finding("/home/x/old.txt", str(src), "Known exploit", old_time)

    recent = db.daily_stats(days=1)
    assert recent == []  # nothing counted as "today"
    historical = db.daily_stats(days=30)
    assert len(historical) == 1
    assert historical[0][0] == time.strftime("%Y-%m-%d", time.gmtime(old_time))
    assert historical[0][4] == 1  # quarantined, credited to the historical day


def test_rebuild_daily_stats_recomputes_from_scratch(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/var/www", 10, [("/x", "r")], duration=3.0)
    # simulate corruption/drift
    conn = db._connect()
    conn.execute("UPDATE daily_stats SET scan_count = 999")
    conn.commit()
    conn.close()

    db.rebuild_daily_stats()
    rows = db.daily_stats(days=1)
    assert rows[0][1] == 1  # back to the real count


def test_daily_stats_excludes_old_dates_outside_window(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "quarantine"))
    src = tmp_path / "ancient.txt"
    src.write_text("x")
    ancient = time.time() - 400 * 86400
    db.import_quarantined_finding("/x", str(src), "r", ancient)
    assert db.daily_stats(days=30) == []


def test_daily_stats_filled_always_returns_exactly_n_days(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/var/www", 10, [("/x", "r")], duration=1.0)  # only today has real data
    rows = db.daily_stats_filled(30)
    assert len(rows) == 30


def test_daily_stats_filled_zero_fills_gaps(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    db.record_scan("/var/www", 10, [("/x", "r")])
    rows = db.daily_stats_filled(7)
    today = time.strftime("%Y-%m-%d", time.gmtime())
    for date, scan_count, files_scanned, hits, quarantined, avg_duration in rows:
        if date == today:
            assert scan_count == 1
        else:
            assert (scan_count, files_scanned, hits, quarantined) == (0, 0, 0, 0)


def test_daily_stats_filled_oldest_first_and_includes_today_last(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    rows = db.daily_stats_filled(7)
    dates = [r[0] for r in rows]
    assert dates == sorted(dates)
    # daily_stats_filled() uses datetime.date.today() (local time, since
    # that's what a local admin means by "today" on the dashboard) - this
    # must compare against the same clock, not time.gmtime(), or the two
    # disagree for a few hours around local midnight in any timezone
    # ahead of UTC.
    assert dates[-1] == datetime.date.today().isoformat()
