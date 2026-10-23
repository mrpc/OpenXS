"""Unit tests for migrate_from_cxs.py."""
import base64
import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import migrate_from_cxs as mig


REAL_CRON_LINE = ("7 0 * * * root /usr/sbin/cxs --xtra /etc/cxs/cxs.xtra "
                   "--report /var/log/cxsreports/scandaily.log --mail root --smtp --quiet --nosummary "
                   "--www --virusscan --noexploitscan --voptions fmMhexT --all --smtp "
                   "--mail mrpc@pramnoshosting.gr --options mMOLfuSGchexdnwZRrD --ctime 25 "
                   "--qoptions Mv --quarantine /home/quarantine")


def test_parse_cron_line_extracts_recognized_flags():
    s = mig.parse_cron_line(REAL_CRON_LINE)
    assert s["mail"] == "mrpc@pramnoshosting.gr"  # last --mail wins
    assert s["www"] is True
    assert s["allusers"] is True
    assert s["virusscan"] is True
    assert s["exploitscan"] is False
    assert s["ctime"] == "25"
    assert s["qoptions"] == "Mv"
    assert s["quarantine"] == "/home/quarantine"
    # --smtp/--quiet/--nosummary/--voptions have no OpenXS equivalent at
    # all (voptions is itself deprecated/[removed] per cxs's own --help)
    # - correctly surfaced, not silently absorbed
    assert "--smtp" in s["_unrecognized"]
    assert "--voptions" in s["_unrecognized"]


def test_translate_settings_assumes_cxs_default_qoptions_when_quarantine_set_without_it():
    conf, warnings = mig.translate_settings({"quarantine": "/home/quarantine"})
    assert set(conf["QUARANTINE_CATEGORIES"].split(",")) == {"yara", "virus"}
    assert any("assumed cxs's own documented default" in w for w in warnings)


def test_translate_settings_maps_qoptions_to_categories():
    conf, warnings = mig.translate_settings({"qoptions": "Mv", "allusers": True, "www": True})
    assert set(conf["QUARANTINE_CATEGORIES"].split(",")) == {"yara", "virus"}
    assert conf["SCAN_MODE"] == "accounts"
    assert conf["ACCOUNTS_SUBPATH"] == "public_html"


def test_translate_settings_reports_unsupported_qoptions():
    conf, warnings = mig.translate_settings({"qoptions": "MvB"})
    assert any("B (" in w for w in warnings)
    assert "B" not in conf["QUARANTINE_CATEGORIES"]


def test_translate_settings_appends_at_localhost_to_bare_mail():
    conf, _ = mig.translate_settings({"mail": "root"})
    assert conf["EMAIL"] == "root@localhost"


def test_translate_settings_flags_virusscan_and_noexploitscan():
    conf, warnings = mig.translate_settings({"virusscan": True, "exploitscan": False})
    assert any("virusscan" in w for w in warnings)
    assert any("noexploitscan" in w for w in warnings)


def test_translate_settings_flags_probability_as_unsupported():
    conf, warnings = mig.translate_settings({"probability": True})
    assert any("Bayesian" in w or "probability" in w for w in warnings)


def test_translate_ignore_maps_file_dir_sym_directly():
    entries, warnings = mig.translate_ignore([
        "file:/home/user/backup.zip",
        "dir:/home/user/tmp",
        "sym:/home/user/link",
    ])
    assert entries == ["/home/user/backup.zip", "/home/user/tmp", "/home/user/link"]
    assert warnings == []


def test_translate_ignore_migrates_regex_entries_as_regex_ignore():
    entries, warnings = mig.translate_ignore(["pfile:\\.bak$"])
    assert entries == ["regex:\\.bak$"]
    assert len(warnings) == 1


def test_translate_ignore_maps_homedir_relative_variants():
    entries, warnings = mig.translate_ignore(["hdir:/tmp", "hfile:/public_html/x.cgi", "hsym:/access-logs"])
    assert entries == ["/tmp", "/public_html/x.cgi", "/access-logs"]
    assert len(warnings) == 3


def test_translate_ignore_maps_md5sum_and_sha256_directly():
    entries, warnings = mig.translate_ignore(["md5sum:deadbeef", "sha256:cafef00d"])
    assert entries == ["md5:deadbeef", "sha256:cafef00d"]
    assert warnings == []


def test_translate_ignore_flags_fp_and_ip_as_unsupported():
    entries, warnings = mig.translate_ignore(["fp:P1419", "ip:1.2.3.4"])
    assert entries == []
    assert len(warnings) == 2


def test_translate_ignore_skips_comments_and_blank_lines():
    entries, warnings = mig.translate_ignore(["# a comment", "", "file:/x"])
    assert entries == ["/x"]


def test_translate_xtra_maps_md5sum_and_sha256():
    entries, warnings = mig.translate_xtra(["md5sum:deadbeef", "sha256:cafef00d"])
    assert entries == ["md5:deadbeef", "sha256:cafef00d"]
    assert warnings == []


def test_translate_xtra_migrates_regall_with_a_warning():
    entries, warnings = mig.translate_xtra(["regall:eval\\(base64_decode"])
    assert entries == ["eval\\(base64_decode"]
    assert len(warnings) == 1


def test_translate_xtra_flags_regfile_as_not_migrated():
    entries, warnings = mig.translate_xtra(["regfile:\\.pl$"])
    assert entries == []
    assert len(warnings) == 1


def test_translate_xtra_strips_quarantine_modifier_with_warning():
    entries, warnings = mig.translate_xtra(["regall:quarantine:/etc/passwd"])
    assert entries == ["/etc/passwd"]
    assert any("force-quarantine" in w for w in warnings)


def make_restore4(base, name, actfile, message_text, qtime="1613553947"):
    qfile = base / name
    qfile.write_text("malicious content")
    message_b64 = base64.b64encode(message_text.encode()).decode()
    (base / (name + ".restore4")).write_text(
        f"time={qtime}\nqfile={qfile}\nactfile={actfile}\nmessage={message_b64}\n"
    )
    return qfile


def test_find_cxs_quarantine_entries_parses_restore4(tmp_path):
    user_dir = tmp_path / "cxsuser" / "someuser"
    user_dir.mkdir(parents=True)
    qfile = make_restore4(user_dir, "shell.php.123_1", "/home/someuser/public_html/shell.php",
                           "Known exploit = [Fingerprint Match]")
    entries = mig.find_cxs_quarantine_entries(str(tmp_path))
    assert len(entries) == 1
    assert entries[0]["actfile"] == "/home/someuser/public_html/shell.php"
    assert entries[0]["qfile"] == str(qfile)
    assert entries[0]["message"] == "Known exploit = [Fingerprint Match]"
    assert entries[0]["time"] == "1613553947"


def test_import_quarantine_dry_run_does_not_move_files(tmp_path):
    user_dir = tmp_path / "cxsuser" / "someuser"
    user_dir.mkdir(parents=True)
    qfile = make_restore4(user_dir, "shell.php.123_1", "/home/someuser/public_html/shell.php", "Known exploit")
    imported, skipped = mig.import_quarantine(str(tmp_path), apply=False)
    assert imported == 1
    assert skipped == []
    assert qfile.exists()  # dry run - nothing actually moved


def test_import_quarantine_apply_registers_in_openxs_db(tmp_path, monkeypatch):
    import openxs_db as db
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    monkeypatch.setattr(db, "QUARANTINE_DIR", str(tmp_path / "openxs_quarantine"))

    cxs_dir = tmp_path / "cxs_quarantine"
    user_dir = cxs_dir / "cxsuser" / "someuser"
    user_dir.mkdir(parents=True)
    make_restore4(user_dir, "shell.php.123_1", "/home/someuser/public_html/shell.php", "Known exploit")

    imported, skipped = mig.import_quarantine(str(cxs_dir), apply=True)
    assert imported == 1
    rows = db.quarantined_files()
    assert len(rows) == 1
    assert rows[0][1] == "/home/someuser/public_html/shell.php"


def test_import_quarantine_skips_already_restored_files(tmp_path):
    user_dir = tmp_path / "cxsuser" / "someuser"
    user_dir.mkdir(parents=True)
    qfile = make_restore4(user_dir, "shell.php.123_1", "/home/someuser/public_html/shell.php", "Known exploit")
    qfile.unlink()  # simulate: already restored/deleted outside cxs
    imported, skipped = mig.import_quarantine(str(tmp_path), apply=False)
    assert imported == 0
    assert len(skipped) == 1


def make_cxs_db(path, findings=(), reports=()):
    """findings: list of (timestamp, actfile, message); reports: list of
    (id, timestamp, title, dbreport) - mirrors cxs.db's real schema,
    verified directly against prodserver's own live install."""
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE files (timestamp TEXT, actfile TEXT, message TEXT)")
    conn.execute("CREATE TABLE reports (id INTEGER, timestamp TEXT, title TEXT, dbreport TEXT)")
    conn.executemany("INSERT INTO files (timestamp, actfile, message) VALUES (?, ?, ?)", findings)
    conn.executemany("INSERT INTO reports (id, timestamp, title, dbreport) VALUES (?, ?, ?, ?)", reports)
    conn.commit()
    conn.close()


def test_find_cxs_db_findings_reads_real_schema(tmp_path):
    db_path = tmp_path / "cxs.db"
    make_cxs_db(db_path, findings=[("1613553947", "/home/x/shell.php", "Known exploit")])
    findings = mig.find_cxs_db_findings(str(db_path))
    assert findings == [{"timestamp": "1613553947", "actfile": "/home/x/shell.php", "message": "Known exploit"}]


def test_find_cxs_db_reports_reads_real_schema(tmp_path):
    db_path = tmp_path / "cxs.db"
    make_cxs_db(db_path, reports=[(1, "1613553947", "Scan all (Hits:5)", "full report text")])
    reports = mig.find_cxs_db_reports(str(db_path))
    assert reports == [{"id": 1, "timestamp": "1613553947", "title": "Scan all (Hits:5)", "dbreport": "full report text"}]


def test_import_logs_missing_db_returns_zero(tmp_path):
    assert mig.import_logs(str(tmp_path / "nope.db"), str(tmp_path / "out"), apply=True) == (0, 0)


def test_import_logs_dry_run_writes_nothing(tmp_path):
    db_path = tmp_path / "cxs.db"
    make_cxs_db(db_path, findings=[("1", "/x", "m")], reports=[(1, "1", "t", "report text")])
    finding_count, report_count = mig.import_logs(str(db_path), str(tmp_path / "out"), apply=False)
    assert (finding_count, report_count) == (1, 1)
    assert not (tmp_path / "out").exists()


def test_import_logs_apply_registers_findings_and_archives_reports(tmp_path, monkeypatch):
    import openxs_db as db
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))

    db_path = tmp_path / "cxs.db"
    make_cxs_db(db_path, findings=[("1613553947", "/home/x/shell.php", "Known exploit")],
                reports=[(42, "1613553947", "Scan all (Hits:1)", "the full report text")])
    out_dir = tmp_path / "out"
    finding_count, report_count = mig.import_logs(str(db_path), str(out_dir), apply=True)
    assert (finding_count, report_count) == (1, 1)

    scans = db.recent_scans(limit=1)
    assert scans[0][2] == "migrated from cxs (historical logs)"
    findings = db.findings_for_scan(scans[0][0])
    assert findings[0][1] == "/home/x/shell.php"
    assert findings[0][2] == "Known exploit"

    report_file = out_dir / "1613553947_42.log"
    assert report_file.read_text() == "the full report text"


ENABLED_LINE = "7 0 * * * root /usr/sbin/cxs --quarantine /home/quarantine --allusers"
DISABLED_LINE = "7 0 * * * root /usr/sbin/cxs --noexploitscan --quarantine /home/quarantine --allusers"
QCLEAN_ONLY_LINE = "@weekly root /usr/sbin/cxs --quarantine /home/quarantine --qclean 180 >/dev/null 2>&1"
NOT_CXS_BINARY_LINE = "*/10 * * * * root /etc/cxs/cxsdbupdate.pl > /dev/null 2>&1"


def test_invokes_cxs_binary_true_for_real_binary_paths():
    assert mig._invokes_cxs_binary("cxs --allusers") is True
    assert mig._invokes_cxs_binary("/usr/sbin/cxs --allusers") is True


def test_invokes_cxs_binary_false_for_unrelated_script_with_cxs_in_its_name():
    # A real false positive found on prodserver: cxsdbupdate.pl is part of
    # the cxs suite but isn't the scanning binary itself.
    assert mig._invokes_cxs_binary(NOT_CXS_BINARY_LINE) is False


def test_cron_line_runs_a_scan_false_for_qclean_only():
    assert mig.cron_line_runs_a_scan(QCLEAN_ONLY_LINE) is False


def test_cron_line_runs_a_scan_true_for_allusers():
    assert mig.cron_line_runs_a_scan(ENABLED_LINE) is True


def test_cron_line_runs_a_scan_true_for_user_flag():
    assert mig.cron_line_runs_a_scan("cxs --user someaccount") is True


def test_cron_line_runs_a_scan_true_for_bare_path_resource():
    assert mig.cron_line_runs_a_scan("cxs /home/someuser/public_html") is True


def test_cron_line_has_exploitscan_enabled_false_for_qclean_only_job():
    # The real false positive this was fixed for: a maintenance-only
    # job has nothing to "disable" even without --noexploitscan.
    assert mig.cron_line_has_exploitscan_enabled(QCLEAN_ONLY_LINE) is False


def test_cron_d_files_uses_run_parts_excluding_bak_files(monkeypatch):
    class FakeResult:
        stdout = "/etc/cron.d/cxs-cron\n/etc/cron.d/cxsdb-cron\n"
    def fake_run(args, **kwargs):
        assert args == ["run-parts", "--list", "/etc/cron.d"]
        return FakeResult()
    monkeypatch.setattr(mig.subprocess, "run", fake_run)
    files = mig._cron_d_files()
    assert files == ["/etc/cron.d/cxs-cron", "/etc/cron.d/cxsdb-cron"]
    assert "/etc/cron.d/cxs-cron.bak-20261022" not in files


def test_cron_d_files_falls_back_to_glob_if_run_parts_unavailable(monkeypatch, tmp_path):
    def fake_run(args, **kwargs):
        raise FileNotFoundError("run-parts not found")
    monkeypatch.setattr(mig.subprocess, "run", fake_run)
    (tmp_path / "somejob").write_text("x")
    monkeypatch.setattr(mig.glob, "glob", lambda pattern: [str(tmp_path / "somejob")])
    assert mig._cron_d_files() == [str(tmp_path / "somejob")]


def test_disable_cxs_exploitscan_skips_qclean_and_non_cxs_binary_lines(monkeypatch):
    monkeypatch.setattr(mig, "find_cxs_cron_sources", lambda: [
        ("file", "/etc/cron.d/cxs-cron", ENABLED_LINE),
        ("file", "/etc/cron.d/cxs-weekly", QCLEAN_ONLY_LINE),
    ])
    results = mig.disable_cxs_exploitscan(apply=False)
    assert len(results) == 1
    assert results[0][2] == ENABLED_LINE


def test_cron_line_has_exploitscan_enabled_by_default():
    assert mig.cron_line_has_exploitscan_enabled(ENABLED_LINE) is True


def test_cron_line_has_exploitscan_enabled_false_when_noexploitscan_present():
    assert mig.cron_line_has_exploitscan_enabled(DISABLED_LINE) is False


def test_cron_line_has_exploitscan_enabled_false_on_real_prodserver_line():
    assert mig.cron_line_has_exploitscan_enabled(REAL_CRON_LINE) is False


def test_disable_exploitscan_in_line_appends_flag():
    assert mig.disable_exploitscan_in_line(ENABLED_LINE) == ENABLED_LINE + " --noexploitscan"


def test_disable_cxs_exploitscan_dry_run_skips_already_disabled(monkeypatch):
    monkeypatch.setattr(mig, "find_cxs_cron_sources", lambda: [
        ("file", "/etc/cron.d/cxs", ENABLED_LINE),
        ("file", "/etc/cron.d/cxs-weekly", DISABLED_LINE),
    ])
    results = mig.disable_cxs_exploitscan(apply=False)
    assert len(results) == 1
    assert results[0][2] == ENABLED_LINE


def test_disable_cxs_exploitscan_dry_run_does_not_write(tmp_path, monkeypatch):
    cron_file = tmp_path / "cxs-cron"
    cron_file.write_text(ENABLED_LINE + "\n")
    monkeypatch.setattr(mig, "find_cxs_cron_sources", lambda: [("file", str(cron_file), ENABLED_LINE)])
    mig.disable_cxs_exploitscan(apply=False)
    assert cron_file.read_text() == ENABLED_LINE + "\n"


def test_disable_cxs_exploitscan_apply_rewrites_only_that_line(tmp_path, monkeypatch):
    cron_file = tmp_path / "cxs-cron"
    cron_file.write_text("# a comment\n" + ENABLED_LINE + "\n@weekly root /usr/sbin/cxs --qclean 180\n")
    monkeypatch.setattr(mig, "find_cxs_cron_sources", lambda: [("file", str(cron_file), ENABLED_LINE)])
    results = mig.disable_cxs_exploitscan(apply=True)
    assert len(results) == 1
    content = cron_file.read_text()
    assert ENABLED_LINE + " --noexploitscan" in content
    assert "# a comment" in content  # untouched
    assert "--qclean 180" in content  # untouched


def test_invokes_cxs_suite_includes_binary_and_helper_scripts():
    assert mig._invokes_cxs_suite(ENABLED_LINE) is True
    assert mig._invokes_cxs_suite(NOT_CXS_BINARY_LINE) is True  # /etc/cxs/cxsdbupdate.pl
    assert mig._invokes_cxs_suite("* * * * * root /usr/bin/true") is False


def test_comment_out_cron_line_prefixes_with_marker():
    out = mig.comment_out_cron_line(ENABLED_LINE)
    assert out.startswith("# disabled by OpenXS migration")
    assert ENABLED_LINE in out


def test_disable_cxs_entirely_includes_everything_not_just_scans(monkeypatch):
    monkeypatch.setattr(mig, "find_cxs_cron_sources", lambda match=None: [
        ("file", "/etc/cron.d/cxs-cron", ENABLED_LINE),
        ("file", "/etc/cron.d/cxs-weekly", QCLEAN_ONLY_LINE),
        ("file", "/etc/cron.d/cxsdb-cron", NOT_CXS_BINARY_LINE),
    ])
    monkeypatch.setattr(mig.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("apply=False must not run anything")))
    cron_changes, watch_stopped = mig.disable_cxs_entirely(apply=False)
    assert len(cron_changes) == 3  # qclean and cxsdbupdate.pl both included, unlike disable_cxs_exploitscan
    assert watch_stopped is None


def test_disable_cxs_entirely_apply_rewrites_all_and_stops_watch(tmp_path, monkeypatch):
    cron_file = tmp_path / "cxs-cron"
    cron_file.write_text(ENABLED_LINE + "\n")
    monkeypatch.setattr(mig, "find_cxs_cron_sources", lambda match=None: [("file", str(cron_file), ENABLED_LINE)])

    calls = []
    class FakeResult:
        returncode = 1  # pgrep: no cxswatch process found
    def fake_run(args, **kwargs):
        calls.append(args)
        return FakeResult()
    monkeypatch.setattr(mig.subprocess, "run", fake_run)
    monkeypatch.setattr(mig.time, "sleep", lambda s: None)

    cron_changes, watch_stopped = mig.disable_cxs_entirely(apply=True)
    assert len(cron_changes) == 1
    assert "# disabled by OpenXS migration" in cron_file.read_text()
    assert ["cxs", "--Wstop"] in calls
    assert watch_stopped is True
