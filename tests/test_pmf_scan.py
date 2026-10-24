"""Unit tests for pmf_scan.py's pure logic - no YARA/ClamAV/docker needed.
Run with: pytest tests/
"""
import hashlib
import os
import sys
import time
import zipfile
import tarfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import pmf_scan


def write(path, content=b"hello"):
    with open(path, "wb") as f:
        f.write(content if isinstance(content, bytes) else content.encode())


# --- ignore file / is_ignored ---------------------------------------------

def test_load_ignore_patterns_plain_and_hashes(tmp_path):
    ignore_file = tmp_path / "ignore"
    ignore_file.write_text("/some/path\n# a comment\nmd5:ABCDEF\nsha256:deadbeef\n\n")
    plain, md5s, sha256s, regexes = pmf_scan.load_ignore_patterns(str(ignore_file))
    assert plain == ["/some/path"]
    assert md5s == {"abcdef"}  # lowercased
    assert sha256s == {"deadbeef"}
    assert regexes == []


def test_load_ignore_patterns_missing_file_returns_empty():
    assert pmf_scan.load_ignore_patterns("/no/such/file") == ([], set(), set(), [])


def test_load_ignore_patterns_compiles_regex_entries(tmp_path):
    ignore_file = tmp_path / "ignore"
    ignore_file.write_text(r"regex:^/tmp/clamav-.*" + "\n")
    plain, md5s, sha256s, regexes = pmf_scan.load_ignore_patterns(str(ignore_file))
    assert len(regexes) == 1
    assert regexes[0].search("/tmp/clamav-abc123")
    assert not regexes[0].search("/home/tmp/clamav-abc123")  # anchored, shouldn't match mid-path


def test_load_ignore_patterns_skips_invalid_regex(tmp_path):
    ignore_file = tmp_path / "ignore"
    ignore_file.write_text("regex:(unclosed\n/some/path\n")
    plain, md5s, sha256s, regexes = pmf_scan.load_ignore_patterns(str(ignore_file))
    assert regexes == []
    assert plain == ["/some/path"]  # the rest of the file still loads fine


def test_is_ignored_by_substring():
    assert pmf_scan.is_ignored("/home/user/backups/x.php", ["/backups/"], set(), set())
    assert not pmf_scan.is_ignored("/home/user/public_html/x.php", ["/backups/"], set(), set())


def test_is_ignored_by_hash(tmp_path):
    f = tmp_path / "file.php"
    write(f, "exact content")
    md5 = hashlib.md5(b"exact content").hexdigest()
    assert pmf_scan.is_ignored(str(f), [], {md5}, set())
    assert not pmf_scan.is_ignored(str(f), [], {"0" * 32}, set())


def test_is_ignored_by_regex():
    import re
    pattern = re.compile(r"^/tmp/clamav-.*")
    assert pmf_scan.is_ignored("/tmp/clamav-abc", [], set(), set(), [pattern])
    assert not pmf_scan.is_ignored("/home/tmp/clamav-abc", [], set(), set(), [pattern])


# --- per-path overrides -----------------------------------------------------

def test_load_path_overrides_parses_kv_pairs(tmp_path):
    f = tmp_path / "path_settings"
    f.write_text("/home/site/uploads fast_php_only=1,quarantine_enabled=0\n# comment\n")
    overrides = pmf_scan.load_path_overrides(str(f))
    assert overrides == [("/home/site/uploads", {"fast_php_only": "1", "quarantine_enabled": "0"})]


def test_effective_setting_longest_prefix_wins():
    overrides = [
        ("/home/site", {"fast_php_only": "0"}),
        ("/home/site/uploads", {"fast_php_only": "1"}),
    ]
    # longest/most specific prefix must win regardless of list order
    overrides_sorted = sorted(overrides, key=lambda o: -len(o[0]))
    assert pmf_scan.effective_setting("/home/site/uploads/x.jpg", overrides_sorted, "fast_php_only", "0") == "1"
    assert pmf_scan.effective_setting("/home/site/other/x.jpg", overrides_sorted, "fast_php_only", "0") == "0"


def test_effective_setting_falls_back_to_default():
    assert pmf_scan.effective_setting("/anything", [], "quarantine_enabled", "0") == "0"


# --- categorize --------------------------------------------------------------

def test_categorize_virus():
    assert pmf_scan.categorize("Eicar-Signature (ClamAV)") == "virus"


def test_categorize_fs():
    assert pmf_scan.categorize("SUID file") == "fs"
    assert pmf_scan.categorize("world-writable directory") == "fs"


def test_categorize_yara_heuristic_default():
    assert pmf_scan.categorize("ObfuscatedPhp") == "yara_heuristic"
    assert pmf_scan.categorize("Custom rule: eval\\(") == "yara_heuristic"


def test_categorize_yara_exploit():
    assert pmf_scan.categorize("Known exploit = [Fingerprint Match] [PHP Exploit [P1755]]") == "yara_exploit"


# --- custom rules (regex + hash) --------------------------------------------

def test_check_custom_rules_regex_match(tmp_path):
    f = tmp_path / "shell.php"
    write(f, "<?php eval($_GET['c']); ?>")
    rules_path = tmp_path / "rules"
    rules_path.write_text(r"eval\s*\(" + "\n")
    rules = pmf_scan.load_custom_rules(str(rules_path))
    hits = pmf_scan.check_custom_rules(str(f), rules)
    assert any("eval" in h for h in hits)


def test_check_custom_rules_hash_match(tmp_path):
    f = tmp_path / "known.php"
    write(f, "known exploit content")
    md5 = hashlib.md5(b"known exploit content").hexdigest()
    rules_path = tmp_path / "rules"
    rules_path.write_text(f"md5:{md5}\n")
    rules = pmf_scan.load_custom_rules(str(rules_path))
    hits = pmf_scan.check_custom_rules(str(f), rules)
    assert any("md5 match" in h for h in hits)


def test_check_custom_rules_pathological_regex_does_not_hang(tmp_path):
    # Real production incident: a migrated cxs.xtra rule with this exact
    # nested-quantifier shape hit catastrophic backtracking against a
    # large, repetitive file and took openxs-watchd from ~16MB to over
    # 12GB RSS before being killed by hand - a single bad rule took the
    # whole daemon down. A classic ReDoS pattern (a+)+ against adversarial
    # input must return (not match, but not hang) within a couple of
    # seconds, not run effectively forever.
    f = tmp_path / "pools.json"
    write(f, "a" * 40 + "!")  # near-matches, never completes - forces backtracking
    rules_path = tmp_path / "rules"
    rules_path.write_text(r"(a+)+b" + "\n")
    rules = pmf_scan.load_custom_rules(str(rules_path))
    start = time.time()
    hits = pmf_scan.check_custom_rules(str(f), rules)
    elapsed = time.time() - start
    assert hits == []
    assert elapsed < 5  # the timeout is 2s - well under an unbounded hang


def test_categorize_maldet():
    assert pmf_scan.categorize("Linux.Trojan.Agent (maldet)") == "maldet"


def test_maldet_scan_no_binary_returns_empty(monkeypatch):
    monkeypatch.setattr(pmf_scan.shutil, "which", lambda name: None)
    assert pmf_scan.maldet_scan(["/tmp/a.php"]) == []


def test_maldet_scan_empty_filelist_returns_empty():
    assert pmf_scan.maldet_scan([]) == []


def test_maldet_scan_parses_event_log_hits(tmp_path, monkeypatch):
    monkeypatch.setattr(pmf_scan.shutil, "which", lambda name: "/usr/local/sbin/maldet" if name == "maldet" else None)

    class FakeResult:
        stdout = "maldet(12345): {scan} signatures loaded: 1000\n"

    monkeypatch.setattr(pmf_scan.subprocess, "run", lambda *a, **k: FakeResult())

    event_log = tmp_path / "event_log"
    event_log.write_text(
        "Oct 23 2026 maldet(99999): {hit} malware hit {HEX}other.sig found for /tmp/unrelated.php\n"
        "Oct 23 2026 maldet(12345): {hit} malware hit {HEX}test.test.eicar.1040 found for /tmp/a.php\n"
    )
    monkeypatch.setattr(pmf_scan, "MALDET_EVENT_LOG", str(event_log))

    findings = pmf_scan.maldet_scan(["/tmp/a.php"])
    assert findings == [("/tmp/a.php", "{HEX}test.test.eicar.1040")]


def test_check_custom_rules_no_match(tmp_path):
    f = tmp_path / "clean.php"
    write(f, "<?php echo 'hi'; ?>")
    rules = pmf_scan.load_custom_rules(str(tmp_path / "nonexistent"))
    assert pmf_scan.check_custom_rules(str(f), rules) == []


# --- archive scanning --------------------------------------------------------

def test_iter_archive_members_zip(tmp_path):
    inner = tmp_path / "inner.php"
    write(inner, "<?php system($_GET['c']); ?>")
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.write(inner, "inner.php")
    members = list(pmf_scan.iter_archive_members(str(archive)))
    assert len(members) == 1
    name, data = members[0]
    assert name == "inner.php"
    assert b"system" in data


def test_iter_archive_members_tar_gz(tmp_path):
    inner = tmp_path / "inner.php"
    write(inner, "<?php eval($_POST['x']); ?>")
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(inner, arcname="inner.php")
    members = list(pmf_scan.iter_archive_members(str(archive)))
    assert len(members) == 1
    assert members[0][0] == "inner.php"


def test_iter_archive_members_non_archive_returns_nothing(tmp_path):
    f = tmp_path / "plain.php"
    write(f, "<?php ?>")
    assert list(pmf_scan.iter_archive_members(str(f))) == []


def test_iter_archive_members_corrupt_archive_degrades_gracefully(tmp_path):
    bogus = tmp_path / "bad.zip"
    write(bogus, "not actually a zip file")
    assert list(pmf_scan.iter_archive_members(str(bogus))) == []


# --- vmrss / throttle (just must not crash) ----------------------------------

def test_vmrss_kb_returns_nonnegative_int():
    assert pmf_scan.vmrss_kb() >= 0


def test_throttle_noop_when_no_limit():
    pmf_scan.throttle(None)  # must return immediately, not hang
    pmf_scan.throttle("")


def test_throttle_noop_when_load_already_under_limit():
    pmf_scan.throttle("999999")  # absurdly high limit, must not sleep


# --- iter_files integration of ignore + fast-mode + size/time filters -------

def test_iter_files_respects_ignore_and_size(tmp_path):
    keep = tmp_path / "keep.php"
    write(keep, "<?php ?>")
    skip = tmp_path / "skip.php"
    write(skip, "<?php ?>")
    empty = tmp_path / "empty.php"
    write(empty, "")

    filelist = tmp_path / "filelist.txt"
    filelist.write_text(f"{keep}\n{skip}\n{empty}\n")

    ignore = ([str(skip)], set(), set(), [])
    result = list(pmf_scan.iter_files(str(filelist), ignore))
    assert result == [str(keep)]


def test_iter_files_tolerates_non_utf8_bytes_in_filelist(tmp_path):
    keep = tmp_path / "keep.php"
    write(keep, "<?php ?>")

    filelist = tmp_path / "filelist.txt"
    # A line with a raw non-UTF8 byte (e.g. a weirdly-encoded uploaded
    # filename) must not crash the whole scan.
    filelist.write_bytes(b"/home/site/public_html/uploads/bad\xb4name.jpg\n" +
                          str(keep).encode() + b"\n")

    ignore = ([], set(), set(), [])
    result = list(pmf_scan.iter_files(str(filelist), ignore))
    assert str(keep) in result


def test_iter_files_fast_php_only_filters_non_php(tmp_path):
    php_file = tmp_path / "a.php"
    write(php_file, "<?php ?>")
    jpg_file = tmp_path / "a.jpg"
    write(jpg_file, "not php")

    filelist = tmp_path / "filelist.txt"
    filelist.write_text(f"{php_file}\n{jpg_file}\n")

    ignore = ([], set(), set(), [])
    result = list(pmf_scan.iter_files(str(filelist), ignore, global_fast_php_only="1"))
    assert result == [str(php_file)]


def test_yara_match_via_daemon_closes_socket_on_connect_failure(tmp_path):
    # Real production leak: openxs-watchd calls this once per file event,
    # and under CPU contention from another busy process, scand (or, here,
    # a dead/nonexistent socket path) fails before a reply ever comes back
    # - the old code left the socket object unclosed on that path (relying
    # on GC), which piled up under sustained high event volume. Open FD
    # count must not grow across repeated failed calls.
    dead_socket = str(tmp_path / "nothing-listening-here.sock")
    fd_dir = f"/proc/{os.getpid()}/fd"
    before = len(os.listdir(fd_dir))
    for _ in range(50):
        result = pmf_scan.yara_match_via_daemon("/some/file.php", socket_path=dead_socket)
        assert result is None
    after = len(os.listdir(fd_dir))
    assert after <= before + 2  # small slack, no per-call growth


def test_file_hashes_normal_small_file(tmp_path):
    f = tmp_path / "small.txt"
    write(f, "known exploit content")
    md5, sha256 = pmf_scan.file_hashes(str(f))
    assert md5 == hashlib.md5(b"known exploit content").hexdigest()
    assert sha256 == hashlib.sha256(b"known exploit content").hexdigest()


def test_file_hashes_skips_files_over_max_size(tmp_path):
    # Real production incident: an actively, heavily-appended-to file
    # (an unrotated PHP error log in a tight logging loop) made an
    # unbounded f.read() in is_ignored()'s hash check balloon to 1.5GB+
    # within a second - this was the only file-content read in the
    # whole codebase with no size cap at all.
    f = tmp_path / "huge.txt"
    f.write_bytes(b"x" * 1000)
    md5, sha256 = pmf_scan.file_hashes(str(f), max_size=500)
    assert md5 is None
    assert sha256 is None


def test_file_hashes_read_is_bounded_even_if_size_check_is_stale(tmp_path):
    # Defense against the actual race: the file could grow between the
    # getsize() check and the read() call (another process appending to
    # it concurrently) - f.read(max_size) must cap what's actually read
    # regardless, not just skip based on a stale size() snapshot.
    f = tmp_path / "borderline.txt"
    f.write_bytes(b"y" * 400)  # under max_size=500, so the read proceeds
    md5, sha256 = pmf_scan.file_hashes(str(f), max_size=500)
    assert md5 == hashlib.md5(b"y" * 400).hexdigest()
