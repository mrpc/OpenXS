"""Unit tests for version_scan.py (WordPress core version check)."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import version_scan as vs


def make_wp_install(tmp_path, name, version):
    wp_root = tmp_path / name
    (wp_root / "wp-includes").mkdir(parents=True)
    (wp_root / "wp-includes" / "version.php").write_text(f"<?php\n$wp_version = '{version}';\n")
    return wp_root


def test_find_wordpress_installs_parses_version(tmp_path):
    make_wp_install(tmp_path, "site1", "6.4.2")
    found = list(vs.find_wordpress_installs(str(tmp_path)))
    assert len(found) == 1
    assert found[0][1] == "6.4.2"


def test_find_wordpress_installs_finds_multiple(tmp_path):
    make_wp_install(tmp_path, "site1", "6.4.2")
    make_wp_install(tmp_path, "site2", "6.0.0")
    found = list(vs.find_wordpress_installs(str(tmp_path)))
    assert len(found) == 2


def test_version_tuple_handles_beta_suffix():
    assert vs._version_tuple("6.4-beta1-12345") == (6, 4)


def test_check_flags_outdated(tmp_path, monkeypatch):
    make_wp_install(tmp_path, "old-site", "5.0")
    monkeypatch.setattr(vs, "latest_wordpress_version", lambda timeout=5: "6.4.2")
    results = vs.check_wordpress(str(tmp_path))
    assert results == [(str(tmp_path / "old-site"), "5.0", "6.4.2", True)]


def test_check_does_not_flag_current(tmp_path, monkeypatch):
    make_wp_install(tmp_path, "current-site", "6.4.2")
    monkeypatch.setattr(vs, "latest_wordpress_version", lambda timeout=5: "6.4.2")
    results = vs.check_wordpress(str(tmp_path))
    assert results[0][3] is False


def test_check_gracefully_handles_unreachable_api(tmp_path, monkeypatch):
    make_wp_install(tmp_path, "site", "6.4.2")
    monkeypatch.setattr(vs, "latest_wordpress_version", lambda timeout=5: None)
    results = vs.check_wordpress(str(tmp_path))
    assert results[0][3] is False  # never flagged outdated when we can't compare


def make_composer_lock(tmp_path, name, packages):
    (tmp_path / name).mkdir(parents=True, exist_ok=True)
    (tmp_path / name / "composer.lock").write_text(json.dumps({
        "packages": [{"name": n, "version": v} for n, v in packages],
        "packages-dev": [],
    }))


def test_find_composer_locks_skips_nested_vendor_dirs(tmp_path):
    make_composer_lock(tmp_path, "site", [("acme/pkg", "1.0.0")])
    make_composer_lock(tmp_path / "site" / "vendor" / "acme" / "pkg", "", [("nested/pkg", "1.0.0")])
    found = list(vs.find_composer_locks(str(tmp_path)))
    assert len(found) == 1


def test_installed_packages_reads_name_and_version(tmp_path):
    make_composer_lock(tmp_path, "site", [("acme/pkg", "2.3.1")])
    pkgs = list(vs.installed_packages(str(tmp_path / "site" / "composer.lock")))
    assert pkgs == [("acme/pkg", "2.3.1")]


def test_latest_package_version_caches_and_skips_repeat_queries(tmp_path, monkeypatch):
    monkeypatch.setattr(vs, "PACKAGE_CACHE_DB", str(tmp_path / "cache.db"))
    calls = []

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self):
            return json.dumps({"packages": {"acme/pkg": [{"version": "2.0.0"}]}}).encode()

    def fake_urlopen(url, timeout=5):
        calls.append(url)
        return FakeResp()

    monkeypatch.setattr(vs.urllib.request, "urlopen", fake_urlopen)
    conn = vs._package_cache_connect()
    assert vs.latest_package_version("acme/pkg", conn) == "2.0.0"
    assert vs.latest_package_version("acme/pkg", conn) == "2.0.0"
    assert len(calls) == 1  # second call was a cache hit, no second HTTP request
    conn.close()


def test_latest_package_version_caches_unknown_packages_too(tmp_path, monkeypatch):
    monkeypatch.setattr(vs, "PACKAGE_CACHE_DB", str(tmp_path / "cache.db"))
    calls = []

    def fake_urlopen(url, timeout=5):
        calls.append(url)
        raise Exception("404")

    monkeypatch.setattr(vs.urllib.request, "urlopen", fake_urlopen)
    conn = vs._package_cache_connect()
    assert vs.latest_package_version("nobody/knows-this", conn) is None
    assert vs.latest_package_version("nobody/knows-this", conn) is None
    assert len(calls) == 1
    conn.close()


def test_check_composer_flags_outdated(tmp_path, monkeypatch):
    monkeypatch.setattr(vs, "PACKAGE_CACHE_DB", str(tmp_path / "cache.db"))
    make_composer_lock(tmp_path, "site", [("acme/pkg", "1.0.0")])
    monkeypatch.setattr(vs, "latest_package_version", lambda name, conn, timeout=5: "2.0.0")
    results = vs.check_composer(str(tmp_path))
    assert len(results) == 1
    assert results[0][4] is True  # outdated


def test_check_composer_does_not_flag_dev_versions(tmp_path, monkeypatch):
    monkeypatch.setattr(vs, "PACKAGE_CACHE_DB", str(tmp_path / "cache.db"))
    make_composer_lock(tmp_path, "site", [("acme/pkg", "dev-main")])
    results = vs.check_composer(str(tmp_path))
    assert results[0][4] is False


def test_record_findings_writes_outdated_hits_tagged_oldversion(tmp_path, monkeypatch):
    import openxs_db as db
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    wp_results = [(str(tmp_path / "wp"), "5.0", "6.4.2", True), (str(tmp_path / "wp2"), "6.4.2", "6.4.2", False)]
    composer_results = [(str(tmp_path / "composer.lock"), "acme/pkg", "1.0.0", "2.0.0", True)]
    vs.record_findings(str(tmp_path), wp_results, composer_results)
    scans = db.recent_scans(limit=1)
    findings = db.findings_for_scan(scans[0][0])
    assert len(findings) == 2  # only the outdated ones, not the up-to-date wp2
    assert all(f[2].endswith("(oldversion)") for f in findings)


def test_record_findings_does_nothing_when_all_up_to_date(tmp_path, monkeypatch):
    import openxs_db as db
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    wp_results = [(str(tmp_path / "wp"), "6.4.2", "6.4.2", False)]
    vs.record_findings(str(tmp_path), wp_results, [])
    assert not os.path.exists(str(tmp_path / "openxs.db"))  # never even connects
