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
    vs.record_findings(str(tmp_path), wp_results, [], [], [], [], [], composer_results)
    scans = db.recent_scans(limit=1)
    findings = db.findings_for_scan(scans[0][0])
    assert len(findings) == 2  # only the outdated ones, not the up-to-date wp2
    assert all(f[2].endswith("(oldversion)") for f in findings)


def test_record_findings_does_nothing_when_all_up_to_date(tmp_path, monkeypatch):
    import openxs_db as db
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    wp_results = [(str(tmp_path / "wp"), "6.4.2", "6.4.2", False)]
    vs.record_findings(str(tmp_path), wp_results, [], [], [], [], [], [])
    assert not os.path.exists(str(tmp_path / "openxs.db"))  # never even connects


# --- Revive Adserver ---------------------------------------------------

def make_revive_install(tmp_path, name, version):
    root = tmp_path / name
    root.mkdir(parents=True)
    (root / "adview.php").write_text("<?php // delivery script\n")
    (root / "constants.php").write_text(f"<?php\ndefine('VERSION', '{version}');\n")
    return root


def test_find_revive_installs_parses_version(tmp_path):
    make_revive_install(tmp_path, "adserver", "6.0.8")
    found = list(vs.find_revive_installs(str(tmp_path)))
    assert len(found) == 1
    assert found[0][1] == "6.0.8"


def test_find_revive_installs_requires_adview_php_too(tmp_path):
    # constants.php alone is too generic a filename to key off safely
    root = tmp_path / "notrevive"
    root.mkdir()
    (root / "constants.php").write_text("<?php\ndefine('VERSION', '1.0');\n")
    assert list(vs.find_revive_installs(str(tmp_path))) == []


def test_check_revive_flags_outdated(tmp_path, monkeypatch):
    make_revive_install(tmp_path, "old-adserver", "5.5.0")
    monkeypatch.setattr(vs, "latest_revive_version", lambda timeout=5: "6.0.8")
    results = vs.check_revive(str(tmp_path))
    assert results == [(str(tmp_path / "old-adserver"), "5.5.0", "6.0.8", True)]


def test_check_revive_does_not_flag_current(tmp_path, monkeypatch):
    make_revive_install(tmp_path, "current-adserver", "6.0.8")
    monkeypatch.setattr(vs, "latest_revive_version", lambda timeout=5: "6.0.8")
    results = vs.check_revive(str(tmp_path))
    assert results[0][3] is False


def test_latest_revive_version_picks_highest_by_version_not_api_order(monkeypatch):
    # GitHub's tags API order isn't guaranteed to be newest-first -
    # must compare by actual version, not trust list position.
    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return json.dumps([{"name": "v6.0.8"}, {"name": "v6.0.10"}, {"name": "v6.0.9"}]).encode()

    monkeypatch.setattr(vs.urllib.request, "urlopen", lambda url, timeout=5: FakeResp())
    assert vs.latest_revive_version() == "6.0.10"


# --- Drupal 7 ------------------------------------------------------------

def make_drupal_install(tmp_path, name, version):
    root = tmp_path / name
    (root / "includes").mkdir(parents=True)
    (root / "modules").mkdir()
    (root / "sites").mkdir()
    (root / "includes" / "bootstrap.inc").write_text(f"<?php\ndefine('VERSION', '{version}');\n")
    return root


def test_find_drupal_installs_parses_version(tmp_path):
    make_drupal_install(tmp_path, "site1", "7.32")
    found = list(vs.find_drupal_installs(str(tmp_path)))
    assert len(found) == 1
    assert found[0][1] == "7.32"


def test_find_drupal_installs_requires_modules_and_sites_dirs(tmp_path):
    # bootstrap.inc alone is too generic a filename to key off safely
    root = tmp_path / "notdrupal" / "includes"
    root.mkdir(parents=True)
    (root / "bootstrap.inc").write_text("<?php\ndefine('VERSION', '7.0');\n")
    assert list(vs.find_drupal_installs(str(tmp_path))) == []


def test_check_drupal_always_flags_as_unsupported(tmp_path, monkeypatch):
    make_drupal_install(tmp_path, "site", "7.103")
    monkeypatch.setattr(vs, "latest_drupal_7_version", lambda timeout=5: "7.103")
    results = vs.check_drupal(str(tmp_path))
    assert results == [(str(tmp_path / "site"), "7.103", "7.103", False, True)]


def test_check_drupal_flags_outdated_within_branch_too(tmp_path, monkeypatch):
    make_drupal_install(tmp_path, "old-site", "7.32")
    monkeypatch.setattr(vs, "latest_drupal_7_version", lambda timeout=5: "7.103")
    results = vs.check_drupal(str(tmp_path))
    assert results == [(str(tmp_path / "old-site"), "7.32", "7.103", True, True)]


def test_record_findings_always_records_drupal_installs(tmp_path, monkeypatch):
    import openxs_db as db
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "openxs.db"))
    drupal_results = [(str(tmp_path / "site"), "7.103", "7.103", False, True)]
    vs.record_findings(str(tmp_path), [], [], drupal_results, [], [], [], [])
    scans = db.recent_scans(limit=1)
    findings = db.findings_for_scan(scans[0][0])
    assert len(findings) == 1
    assert "end of life" in findings[0][2]
    assert findings[0][2].endswith("(oldversion)")


# --- Joomla ----------------------------------------------------------------

def make_joomla_install(tmp_path, name, version):
    root = tmp_path / name
    (root / "administrator" / "manifests" / "files").mkdir(parents=True)
    (root / "administrator" / "manifests" / "files" / "joomla.xml").write_text(
        f"<?xml version=\"1.0\"?>\n<extension><version>{version}</version></extension>\n")
    return root


def test_find_joomla_installs_parses_version(tmp_path):
    make_joomla_install(tmp_path, "site1", "2.5.28")
    found = list(vs.find_joomla_installs(str(tmp_path)))
    assert len(found) == 1
    assert found[0][1] == "2.5.28"


def test_find_joomla_installs_ignores_manifest_outside_administrator_dir(tmp_path):
    # a "manifests/files/joomla.xml" not actually nested under an
    # administrator/ dir isn't a real Joomla install root
    root = tmp_path / "notjoomla" / "manifests" / "files"
    root.mkdir(parents=True)
    (root / "joomla.xml").write_text("<extension><version>1.0</version></extension>")
    assert list(vs.find_joomla_installs(str(tmp_path))) == []


def test_check_joomla_flags_old_major_branch_as_unsupported(tmp_path, monkeypatch):
    make_joomla_install(tmp_path, "old-site", "2.5.28")
    monkeypatch.setattr(vs, "latest_joomla_version", lambda timeout=5: "5.1.0")
    results = vs.check_joomla(str(tmp_path))
    assert results == [(str(tmp_path / "old-site"), "2.5.28", "5.1.0", True, True)]


def test_check_joomla_does_not_flag_current_supported_branch(tmp_path, monkeypatch):
    make_joomla_install(tmp_path, "current-site", "5.1.0")
    monkeypatch.setattr(vs, "latest_joomla_version", lambda timeout=5: "5.1.0")
    results = vs.check_joomla(str(tmp_path))
    assert results == [(str(tmp_path / "current-site"), "5.1.0", "5.1.0", False, False)]


# --- WordPress plugins/themes ----------------------------------------------

def make_wp_plugin(wp_root, slug, version, via="readme"):
    plugin_dir = wp_root / "wp-content" / "plugins" / slug
    plugin_dir.mkdir(parents=True)
    if via == "readme":
        (plugin_dir / "readme.txt").write_text(f"=== {slug} ===\nStable tag: {version}\n")
    else:
        (plugin_dir / f"{slug}.php").write_text(
            f"<?php\n/**\n * Plugin Name: {slug}\n * Version: {version}\n */\n")


def make_wp_theme(wp_root, slug, version):
    theme_dir = wp_root / "wp-content" / "themes" / slug
    theme_dir.mkdir(parents=True)
    (theme_dir / "style.css").write_text(f"/*\nTheme Name: {slug}\nVersion: {version}\n*/\n")


def test_find_wp_plugins_reads_stable_tag_from_readme(tmp_path):
    make_wp_plugin(tmp_path, "akismet", "5.3")
    found = list(vs.find_wp_plugins(str(tmp_path)))
    assert found == [("akismet", "5.3")]


def test_find_wp_plugins_falls_back_to_php_header(tmp_path):
    make_wp_plugin(tmp_path, "my-plugin", "1.2.0", via="header")
    found = list(vs.find_wp_plugins(str(tmp_path)))
    assert found == [("my-plugin", "1.2.0")]


def test_find_wp_plugins_ignores_trunk_stable_tag(tmp_path):
    plugin_dir = tmp_path / "wp-content" / "plugins" / "dev-plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "readme.txt").write_text("Stable tag: trunk\n")
    assert list(vs.find_wp_plugins(str(tmp_path))) == []


def test_find_wp_themes_reads_style_css_header(tmp_path):
    make_wp_theme(tmp_path, "twentytwentyfour", "1.2")
    found = list(vs.find_wp_themes(str(tmp_path)))
    assert found == [("twentytwentyfour", "1.2")]


def test_check_wp_plugins_flags_outdated(tmp_path, monkeypatch):
    monkeypatch.setattr(vs, "PACKAGE_CACHE_DB", str(tmp_path / "cache.db"))
    wp_root = make_wp_install(tmp_path, "site", "6.4.2")
    make_wp_plugin(wp_root, "akismet", "5.0")
    monkeypatch.setattr(vs, "_latest_wp_asset_version", lambda kind, slug, conn, timeout=5: "5.3")
    wp_results = [(str(wp_root), "6.4.2", "6.4.2", False)]
    results = vs.check_wp_plugins(wp_results)
    assert results == [(str(wp_root), "akismet", "5.0", "5.3", True)]


def test_check_wp_themes_flags_outdated(tmp_path, monkeypatch):
    monkeypatch.setattr(vs, "PACKAGE_CACHE_DB", str(tmp_path / "cache.db"))
    wp_root = make_wp_install(tmp_path, "site", "6.4.2")
    make_wp_theme(wp_root, "twentytwentyfour", "1.0")
    monkeypatch.setattr(vs, "_latest_wp_asset_version", lambda kind, slug, conn, timeout=5: "1.2")
    wp_results = [(str(wp_root), "6.4.2", "6.4.2", False)]
    results = vs.check_wp_themes(wp_results)
    assert results == [(str(wp_root), "twentytwentyfour", "1.0", "1.2", True)]


def test_latest_wp_asset_version_caches_and_skips_repeat_queries(tmp_path, monkeypatch):
    monkeypatch.setattr(vs, "PACKAGE_CACHE_DB", str(tmp_path / "cache.db"))
    calls = []

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self):
            return json.dumps({"version": "5.3"}).encode()

    def fake_urlopen(url, timeout=5):
        calls.append(url)
        return FakeResp()

    monkeypatch.setattr(vs.urllib.request, "urlopen", fake_urlopen)
    conn = vs._wp_asset_cache_connect()
    assert vs._latest_wp_asset_version("plugin", "akismet", conn) == "5.3"
    assert vs._latest_wp_asset_version("plugin", "akismet", conn) == "5.3"
    assert len(calls) == 1
    conn.close()
