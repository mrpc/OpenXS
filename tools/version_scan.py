#!/usr/bin/env python3
"""Initial, narrow version of cxs's `sversionscan` (vulnerable CMS/plugin
version detection):
  - WordPress core only for CMS detection, since that's the only CMS type
    actually found installed across our fleet so far (see TIMELINE.md). A
    full generic version is a different, much bigger problem (plugin-
    level CVE matching needs a vulnerability database we don't have) -
    this just answers the simpler, immediately useful question: is
    WordPress core itself out of date on this server.
  - Composer packages more generally: reads every composer.lock found
    under the scan root and checks each installed package's version
    against Packagist's latest - this needs no built-in knowledge of any
    specific package (our own framework included), it just asks
    Packagist. A small SQLite cache (package name -> latest version)
    avoids asking Packagist the same question for the same package on
    every single site that happens to depend on it.

Report-only, like the other checkers here.
"""
import json
import os
import re
import sqlite3
import sys
import time
import urllib.request

WP_VERSION_RE = re.compile(r"""\$wp_version\s*=\s*['"]([^'"]+)['"]""")
LATEST_VERSION_URL = "https://api.wordpress.org/core/version-check/1.7/"
REVIVE_VERSION_RE = re.compile(r"""define\s*\(\s*['"]VERSION['"]\s*,\s*['"]([^'"]+)['"]\s*\)""")
REVIVE_TAGS_URL = "https://api.github.com/repos/revive-adserver/revive-adserver/tags?per_page=30"
DRUPAL_VERSION_RE = re.compile(r"""define\s*\(\s*['"]VERSION['"]\s*,\s*['"](7\.[^'"]+)['"]\s*\)""")
DRUPAL_RELEASE_HISTORY_URL = "https://updates.drupal.org/release-history/drupal/7.x"
# Only digits/dots captured (not [^'"]+) - the real value has a trailing
# space inside the quotes (define('RCMAIL_VERSION', '1.3.1 ');, confirmed
# by hand on a real install), which [^'"]+ would otherwise capture too.
ROUNDCUBE_VERSION_RE = re.compile(r"""define\s*\(\s*['"]RCMAIL_VERSION['"]\s*,\s*['"]([\d.]+)""")
PHPMYADMIN_VERSION_RE = re.compile(r'"version"\s*:\s*"([\d.]+)"')
JOOMLA_MANIFEST_RELPATH = os.path.join("administrator", "manifests", "files", "joomla.xml")
JOOMLA_VERSION_RE = re.compile(r"<version>([^<]+)</version>")
JOOMLA_TAGS_URL = "https://api.github.com/repos/joomla/joomla-cms/tags?per_page=100"
WP_PLUGIN_VERSION_RE = re.compile(r"""^\s*\*?\s*(?:Stable tag|Version)\s*:\s*(\S+)""", re.IGNORECASE | re.MULTILINE)
WP_PLUGIN_INFO_URL = "https://api.wordpress.org/plugins/info/1.0/{slug}.json"
WP_THEME_INFO_URL = "https://api.wordpress.org/themes/info/1.0/{slug}.json"
PACKAGIST_URL = "https://repo.packagist.org/p2/{name}.json"
PACKAGE_CACHE_DB = os.environ.get("OPENXS_PACKAGE_CACHE_DB", "/var/lib/openxs/package_versions.db")
PACKAGE_CACHE_TTL = 7 * 24 * 3600  # re-check a package at most once a week


def find_wordpress_installs(root):
    """Yields (wp_root_dir, installed_version) for every WordPress install
    found under root."""
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.basename(dirpath) == "wp-includes" and "version.php" in filenames:
            try:
                with open(os.path.join(dirpath, "version.php"), errors="replace") as f:
                    m = WP_VERSION_RE.search(f.read())
            except OSError:
                continue
            if m:
                yield os.path.dirname(dirpath), m.group(1)
            dirnames[:] = []  # don't descend into wp-includes itself


def latest_wordpress_version(timeout=5):
    """None if unreachable - a server without outbound internet (or a
    blocked one) shouldn't make this check crash or false-flag everything
    as outdated."""
    try:
        with urllib.request.urlopen(LATEST_VERSION_URL, timeout=timeout) as resp:
            data = json.loads(resp.read())
        return data["offers"][0]["current"]
    except Exception:
        return None


def find_revive_installs(root):
    """Yields (install_root, installed_version) for every Revive Adserver
    (the maintained, actively-developed fork of the old OpenX Adserver)
    install found under root. constants.php alone is too generic a
    filename to key off safely - also requires adview.php alongside it,
    one of Revive's own top-level delivery scripts."""
    for dirpath, dirnames, filenames in os.walk(root):
        if "constants.php" in filenames and "adview.php" in filenames:
            try:
                with open(os.path.join(dirpath, "constants.php"), errors="replace") as f:
                    m = REVIVE_VERSION_RE.search(f.read())
            except OSError:
                continue
            if m:
                yield dirpath, m.group(1)
            dirnames[:] = []  # don't descend into a Revive install's own internals


def latest_revive_version(timeout=5):
    """None if unreachable. Revive Adserver doesn't use GitHub's Releases
    feature, only plain tags (v6.0.8, ...) - picks the highest by actual
    version comparison, not whatever order the API happens to return."""
    try:
        with urllib.request.urlopen(REVIVE_TAGS_URL, timeout=timeout) as resp:
            data = json.loads(resp.read())
        versions = [t["name"].lstrip("v") for t in data if t.get("name", "").lstrip("v")]
        return max(versions, key=_version_tuple) if versions else None
    except Exception:
        return None


def check_revive(root):
    """Returns a list of (install_root, installed, latest, outdated) tuples."""
    latest = latest_revive_version()
    results = []
    for install_root, installed in find_revive_installs(root):
        outdated = latest is not None and _version_tuple(installed) < _version_tuple(latest)
        results.append((install_root, installed, latest, outdated))
    return results


def find_drupal_installs(root):
    """Yields (install_root, installed_version) for every Drupal 7
    install found under root. bootstrap.inc alone is too generic a
    filename to key off safely - also requires modules/ and sites/
    alongside it, Drupal's own top-level directory layout."""
    for dirpath, dirnames, filenames in os.walk(root):
        if (os.path.basename(dirpath) == "includes" and "bootstrap.inc" in filenames
                and os.path.isdir(os.path.join(os.path.dirname(dirpath), "modules"))
                and os.path.isdir(os.path.join(os.path.dirname(dirpath), "sites"))):
            try:
                with open(os.path.join(dirpath, "bootstrap.inc"), errors="replace") as f:
                    m = DRUPAL_VERSION_RE.search(f.read())
            except OSError:
                continue
            if m:
                yield os.path.dirname(dirpath), m.group(1)
            dirnames[:] = []  # don't descend into includes/ itself


def latest_drupal_7_version(timeout=5):
    """None if unreachable. Drupal 7 as a whole branch is unsupported
    (no more security advisories) independent of patch level - this is
    only about whether a newer 7.x bug-fix release exists, a much
    smaller concern than that fact itself."""
    try:
        with urllib.request.urlopen(DRUPAL_RELEASE_HISTORY_URL, timeout=timeout) as resp:
            xml = resp.read().decode("utf-8", errors="replace")
        versions = re.findall(r"<version>(7\.\d+)</version>", xml)
        return max(versions, key=_version_tuple) if versions else None
    except Exception:
        return None


def check_drupal(root):
    """Returns a list of (install_root, installed, latest, outdated,
    branch_unsupported) tuples. branch_unsupported is always True here
    - Drupal 7 itself reached end of life (no more official security
    coverage) regardless of how current a 7.x install is, which matters
    more than whether it's merely behind the latest 7.x point release."""
    latest = latest_drupal_7_version()
    results = []
    for install_root, installed in find_drupal_installs(root):
        outdated = latest is not None and _version_tuple(installed) < _version_tuple(latest)
        results.append((install_root, installed, latest, outdated, True))
    return results


def find_joomla_installs(root):
    """Yields (install_root, installed_version) for every Joomla install
    found under root. administrator/manifests/files/joomla.xml is a
    single, stable marker across Joomla's whole history (1.6 through
    5.x) with its own <version>X.Y.Z</version>, unlike the internal
    version-class file whose format/location changed across major
    versions (JVersion properties pre-4.0, Version:: constants 4.0+)."""
    for dirpath, dirnames, filenames in os.walk(root):
        manifest = os.path.join(dirpath, JOOMLA_MANIFEST_RELPATH)
        if os.path.isdir(os.path.join(dirpath, "administrator")) and os.path.isfile(manifest):
            try:
                with open(manifest, errors="replace") as f:
                    m = JOOMLA_VERSION_RE.search(f.read())
            except OSError:
                continue
            if m:
                yield dirpath, m.group(1)
            dirnames[:] = [d for d in dirnames if d != "administrator"]


def latest_joomla_version(timeout=5):
    """None if unreachable. Joomla doesn't use GitHub Releases consistently
    across its whole history either - plain tags, same approach as Revive."""
    try:
        with urllib.request.urlopen(JOOMLA_TAGS_URL, timeout=timeout) as resp:
            data = json.loads(resp.read())
        versions = [t["name"].lstrip("v") for t in data if re.match(r"^v?\d+\.\d+\.\d+$", t.get("name", ""))]
        return max(versions, key=_version_tuple) if versions else None
    except Exception:
        return None


def check_joomla(root):
    """Returns a list of (install_root, installed, latest, outdated,
    branch_unsupported) tuples, same shape as check_drupal. Joomla 1.x/2.x/3.x
    are all end of life (3.x reached EOL 2023-10-17); only 4.x/5.x are
    still officially supported."""
    latest = latest_joomla_version()
    results = []
    for install_root, installed in find_joomla_installs(root):
        major = _version_tuple(installed)[:1]
        branch_unsupported = bool(major) and major[0] < 4
        outdated = latest is not None and _version_tuple(installed) < _version_tuple(latest)
        results.append((install_root, installed, latest, outdated, branch_unsupported))
    return results


def _version_tuple(v):
    # Good enough for "a.b.c" / "a.b" comparisons. Pre-release suffixes
    # (e.g. "6.4-beta1-12345") come after the first '-' - stripped first,
    # otherwise "beta1"'s own digit would be read as a version component.
    return tuple(int(p) for p in re.findall(r"\d+", v.split("-")[0])[:3])


def check_wordpress(root):
    """Returns a list of (wp_root, installed, latest, outdated) tuples."""
    latest = latest_wordpress_version()
    results = []
    for wp_root, installed in find_wordpress_installs(root):
        outdated = latest is not None and _version_tuple(installed) < _version_tuple(latest)
        results.append((wp_root, installed, latest, outdated))
    return results


def check_wordpress_unknown_files(wp_results):
    """(wp_root, abs_path, is_old_leftover) for every file under a
    WordPress install's wp-admin/wp-includes that isn't part of its own
    version's official file list - see
    wp_core_checksums.find_unknown_core_files()'s docstring. Skips an
    install whose version check itself came back unknown (latest is
    None, e.g. unreachable) only in the sense that fetch_checksums()
    there already returns [] rather than guessing when it can't get a
    manifest - this just reuses check_wordpress()'s own install list so
    "every WordPress root already found" isn't walked a second time."""
    import wp_core_checksums
    results = []
    for wp_root, installed, _latest, _outdated in wp_results:
        for abs_path, is_old_leftover in wp_core_checksums.find_unknown_core_files(wp_root, installed):
            results.append((wp_root, abs_path, is_old_leftover))
    return results


DB_SCAN_RULESET = os.environ.get("OPENXS_RULESET", "/opt/php-malware-finder/php.yar")


def check_wordpress_database(wp_results):
    """(wp_root, label, rule_name) for every suspicious hit found in any
    detected WordPress install's own database - see
    wp_db_scan.scan_wp_database()'s docstring. Off by default
    (OPENXS_DB_SCAN_ENABLED) and a complete no-op (not even a yara
    import) unless explicitly turned on - reading a site's own DB
    credentials and connecting to its live database is a bigger step
    than anything file-scanning-only does. Reuses check_wordpress()'s
    own install list rather than walking for WordPress a second time."""
    if os.environ.get("OPENXS_DB_SCAN_ENABLED") != "1":
        return []
    try:
        import pmf_scan
        import wp_db_scan
        rules = pmf_scan.compile_ruleset(DB_SCAN_RULESET)
    except Exception as e:
        print(f"# (database scan skipped: {e})", file=sys.stderr)
        return []
    results = []
    for wp_root, _installed, _latest, _outdated in wp_results:
        for label, rule in wp_db_scan.scan_wp_database(wp_root, rules):
            results.append((wp_root, label, rule))
    return results


def find_wp_plugins(wp_root):
    """Yields (slug, installed_version) for every plugin under a
    WordPress install's wp-content/plugins/ - reads readme.txt's "Stable
    tag:" line (the actual deployed version per WordPress.org convention)
    falling back to any top-level .php file's standard "Version:" header
    comment for plugins that ship without a readme.txt."""
    plugins_dir = os.path.join(wp_root, "wp-content", "plugins")
    try:
        slugs = sorted(d for d in os.listdir(plugins_dir) if os.path.isdir(os.path.join(plugins_dir, d)))
    except OSError:
        return
    for slug in slugs:
        plugin_dir = os.path.join(plugins_dir, slug)
        version = None
        readme = os.path.join(plugin_dir, "readme.txt")
        if os.path.isfile(readme):
            try:
                with open(readme, errors="replace") as f:
                    m = re.search(r"^\s*Stable tag\s*:\s*(\S+)", f.read(), re.IGNORECASE | re.MULTILINE)
                if m and m.group(1).lower() != "trunk":
                    version = m.group(1)
            except OSError:
                pass
        if version is None:
            try:
                for fn in sorted(os.listdir(plugin_dir)):
                    if not fn.endswith(".php"):
                        continue
                    with open(os.path.join(plugin_dir, fn), errors="replace") as f:
                        m = WP_PLUGIN_VERSION_RE.search(f.read(2048))
                    if m:
                        version = m.group(1)
                        break
            except OSError:
                pass
        if version:
            yield slug, version


def find_wp_themes(wp_root):
    """Yields (slug, installed_version) for every theme under a WordPress
    install's wp-content/themes/ - style.css's standard header comment."""
    themes_dir = os.path.join(wp_root, "wp-content", "themes")
    try:
        slugs = sorted(d for d in os.listdir(themes_dir) if os.path.isdir(os.path.join(themes_dir, d)))
    except OSError:
        return
    for slug in slugs:
        style_css = os.path.join(themes_dir, slug, "style.css")
        try:
            with open(style_css, errors="replace") as f:
                m = WP_PLUGIN_VERSION_RE.search(f.read(2048))
        except OSError:
            continue
        if m:
            yield slug, m.group(1)


def _wp_asset_cache_connect():
    os.makedirs(os.path.dirname(PACKAGE_CACHE_DB), exist_ok=True)
    conn = sqlite3.connect(PACKAGE_CACHE_DB)
    conn.execute("CREATE TABLE IF NOT EXISTS wp_asset_versions "
                 "(kind TEXT NOT NULL, slug TEXT NOT NULL, latest_version TEXT, checked_at REAL NOT NULL, "
                 "PRIMARY KEY (kind, slug))")
    return conn


def _latest_wp_asset_version(kind, slug, conn, timeout=5):
    """kind is "plugin" or "theme". Same cache shape/TTL as Packagist
    lookups - a popular plugin/theme can show up on dozens of sites."""
    row = conn.execute("SELECT latest_version, checked_at FROM wp_asset_versions WHERE kind = ? AND slug = ?",
                        (kind, slug)).fetchone()
    if row and time.time() - row[1] < PACKAGE_CACHE_TTL:
        return row[0]

    latest = None
    try:
        url = (WP_PLUGIN_INFO_URL if kind == "plugin" else WP_THEME_INFO_URL).format(slug=slug)
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read())
        latest = data.get("version") or None
    except Exception:
        pass  # unreachable, not on wordpress.org (premium/custom), or malformed - cached as "unknown" too

    conn.execute("INSERT INTO wp_asset_versions (kind, slug, latest_version, checked_at) VALUES (?, ?, ?, ?) "
                 "ON CONFLICT(kind, slug) DO UPDATE SET latest_version=excluded.latest_version, checked_at=excluded.checked_at",
                 (kind, slug, latest, time.time()))
    conn.commit()
    return latest


def check_wp_plugins(wp_results):
    """Takes check_wordpress()'s own results (so plugins/themes are only
    checked for installs it already found) and returns a list of
    (wp_root, slug, installed, latest, outdated) tuples."""
    conn = _wp_asset_cache_connect()
    results = []
    for wp_root, _installed, _latest, _outdated in wp_results:
        for slug, installed in find_wp_plugins(wp_root):
            latest = _latest_wp_asset_version("plugin", slug, conn)
            outdated = bool(latest and _version_tuple(installed) < _version_tuple(latest))
            results.append((wp_root, slug, installed, latest, outdated))
    conn.close()
    return results


def check_wp_themes(wp_results):
    """Same shape as check_wp_plugins, for themes."""
    conn = _wp_asset_cache_connect()
    results = []
    for wp_root, _installed, _latest, _outdated in wp_results:
        for slug, installed in find_wp_themes(wp_root):
            latest = _latest_wp_asset_version("theme", slug, conn)
            outdated = bool(latest and _version_tuple(installed) < _version_tuple(latest))
            results.append((wp_root, slug, installed, latest, outdated))
    conn.close()
    return results


def find_composer_locks(root):
    for dirpath, dirnames, filenames in os.walk(root):
        if "composer.lock" in filenames:
            yield os.path.join(dirpath, "composer.lock")
            dirnames[:] = [d for d in dirnames if d != "vendor"]  # nested vendor/*/composer.lock isn't ours to report on


def installed_packages(lock_path):
    """Yields (name, version) for every package in a composer.lock -
    production and dev dependencies alike."""
    try:
        with open(lock_path, errors="replace") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return
    for pkg in data.get("packages", []) + data.get("packages-dev", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            yield name, version


def _package_cache_connect():
    os.makedirs(os.path.dirname(PACKAGE_CACHE_DB), exist_ok=True)
    conn = sqlite3.connect(PACKAGE_CACHE_DB)
    conn.execute("CREATE TABLE IF NOT EXISTS package_versions "
                 "(name TEXT PRIMARY KEY, latest_version TEXT, checked_at REAL NOT NULL)")
    return conn


def latest_package_version(name, conn, timeout=5):
    """Cached: a package already asked about recently (PACKAGE_CACHE_TTL)
    isn't asked about again - the same package can show up in dozens of
    composer.lock files across a fleet in one scan run. latest_version is
    stored as NULL for "asked, Packagist doesn't know this package" -
    still a cache hit, not re-queried every time either."""
    row = conn.execute("SELECT latest_version, checked_at FROM package_versions WHERE name = ?",
                        (name,)).fetchone()
    if row and time.time() - row[1] < PACKAGE_CACHE_TTL:
        return row[0]

    latest = None
    try:
        url = PACKAGIST_URL.format(name=name)
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read())
        versions = data["packages"][name]
        latest = versions[0]["version"] if versions else None
    except Exception:
        pass  # unreachable, 404 (not on Packagist), or malformed response - all cached as "unknown" for now

    conn.execute("INSERT INTO package_versions (name, latest_version, checked_at) VALUES (?, ?, ?) "
                 "ON CONFLICT(name) DO UPDATE SET latest_version=excluded.latest_version, checked_at=excluded.checked_at",
                 (name, latest, time.time()))
    conn.commit()
    return latest


def check_composer(root):
    """Returns a list of (lock_path, package, installed, latest, outdated)
    tuples. A dev/VCS-branch version (e.g. "dev-main", not a tagged
    release) can't be meaningfully compared - reported with latest=None,
    same as a package Packagist doesn't know about."""
    conn = _package_cache_connect()
    results = []
    for lock_path in find_composer_locks(root):
        for name, installed in installed_packages(lock_path):
            installed_t = _version_tuple(installed) or None  # empty tuple for a non-numeric dev/VCS version
            latest = latest_package_version(name, conn) if installed_t else None
            outdated = bool(latest and installed_t and installed_t < _version_tuple(latest))
            results.append((lock_path, name, installed, latest, outdated))
    conn.close()
    return results


def record_findings(root, wp_results, revive_results, drupal_results, joomla_results,
                     wp_plugin_results, wp_theme_results, composer_results,
                     wp_unknown_file_results=(), wp_db_results=()):
    """Records OUTDATED hits into OpenXS's own scan-history db (rule_name
    tagged "(oldversion)", same suffix-based convention pmf_scan.py's
    categorize() already uses for "(ClamAV)"/"(maldet)") - so they show
    up in the Webmin dashboard's unified findings browser as their own
    category, same as cxs's own "Old Versions" tab, instead of only
    ever living in a separate version_results.txt no UI reads from."""
    findings = [(wp_root, f"Outdated WordPress core: {installed} (latest: {latest}) (oldversion)")
                for wp_root, installed, latest, outdated in wp_results if outdated]
    findings += [(install_root, f"Outdated Revive Adserver: {installed} (latest: {latest}) (oldversion)")
                 for install_root, installed, latest, outdated in revive_results if outdated]
    findings += [(install_root, f"Drupal core: {installed} - Drupal 7 is end of life, "
                  f"no more official security coverage regardless of patch level"
                  + (f" (also behind latest 7.x: {latest})" if outdated else "") + " (oldversion)")
                 for install_root, installed, latest, outdated, branch_unsupported in drupal_results]
    findings += [(install_root, f"Joomla core: {installed}"
                  + (" - this major branch is end of life, no more official security coverage"
                     if branch_unsupported else f" (latest: {latest})" if outdated else "")
                  + " (oldversion)")
                 for install_root, installed, latest, outdated, branch_unsupported in joomla_results
                 if outdated or branch_unsupported]
    findings += [(wp_root, f"Outdated WordPress plugin {slug}: {installed} (latest: {latest}) (oldversion)")
                 for wp_root, slug, installed, latest, outdated in wp_plugin_results if outdated]
    findings += [(wp_root, f"Outdated WordPress theme {slug}: {installed} (latest: {latest}) (oldversion)")
                 for wp_root, slug, installed, latest, outdated in wp_theme_results if outdated]
    findings += [(lock_path, f"Outdated package {name}: {installed} (latest: {latest}) (oldversion)")
                 for lock_path, name, installed, latest, outdated in composer_results if outdated]
    # Not a version check, but shares this same once-per-scheduled-scan
    # recording pass rather than needing its own - see
    # check_wordpress_unknown_files()/find_unknown_core_files()'s
    # docstrings. "(oldversion)" for the common, low-severity leftover-
    # from-an-update case (same "Old Versions" tab, since that's really
    # what it is); no suffix (falls into the generic yara_heuristic
    # bucket) for a file that matches no known release at all - the
    # more interesting, higher-severity case.
    findings += [(abs_path, f"Old WordPress core file not removed during update: "
                  f"{os.path.relpath(abs_path, wp_root)} (oldversion)")
                 for wp_root, abs_path, is_old_leftover in wp_unknown_file_results if is_old_leftover]
    findings += [(abs_path, f"Unknown file in WordPress core: {os.path.relpath(abs_path, wp_root)}")
                 for wp_root, abs_path, is_old_leftover in wp_unknown_file_results if not is_old_leftover]
    # Not a file-based finding at all (see wp_db_scan.py's docstring) -
    # "(database)" tagged so it's visibly distinct in the findings
    # browser, same suffix-tagging convention as everything else here,
    # though it still falls into the generic yara_heuristic/yara_exploit
    # category bucket by whatever rule actually matched (categorize()
    # only special-cases the (oldversion)/(ClamAV)/(maldet) suffixes).
    findings += [(f"{wp_root} ({label})", f"{rule} (database)")
                 for wp_root, label, rule in wp_db_results]
    if not findings:
        return
    total = (len(wp_results) + len(revive_results) + len(drupal_results) + len(joomla_results)
             + len(wp_plugin_results) + len(wp_theme_results) + len(composer_results)
             + len(wp_unknown_file_results) + len(wp_db_results))
    try:
        import openxs_db
        openxs_db.record_scan(root, total, findings)
    except Exception as e:
        print(f"# (version scan history not recorded: {e})", file=sys.stderr)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <root-dir-to-scan>", file=sys.stderr)
        sys.exit(1)
    root = sys.argv[1]

    wp_results = check_wordpress(root)
    revive_results = check_revive(root)
    drupal_results = check_drupal(root)
    joomla_results = check_joomla(root)
    wp_plugin_results = check_wp_plugins(wp_results)
    wp_theme_results = check_wp_themes(wp_results)
    composer_results = check_composer(root)
    wp_unknown_file_results = check_wordpress_unknown_files(wp_results)
    wp_db_results = check_wordpress_database(wp_results)

    wp_outdated = sum(1 for _, _, _, outdated in wp_results if outdated)
    revive_outdated = sum(1 for _, _, _, outdated in revive_results if outdated)
    drupal_unsupported = len(drupal_results)  # always a finding, branch itself is EOL
    joomla_flagged = sum(1 for _, _, _, outdated, branch_unsupported in joomla_results
                          if outdated or branch_unsupported)
    wp_plugin_outdated = sum(1 for _, _, _, _, outdated in wp_plugin_results if outdated)
    wp_theme_outdated = sum(1 for _, _, _, _, outdated in wp_theme_results if outdated)
    composer_outdated = sum(1 for _, _, _, _, outdated in composer_results if outdated)

    print(f"# WordPress: {len(wp_results)} install(s), {wp_outdated} outdated")
    for wp_root, installed, latest, outdated in wp_results:
        if latest is None:
            print(f"UNKNOWN\t{wp_root}\t{installed}\t(could not reach {LATEST_VERSION_URL})")
        elif outdated:
            print(f"OUTDATED\t{wp_root}\t{installed}\t(latest: {latest})")
        else:
            print(f"OK\t{wp_root}\t{installed}")

    print(f"# WordPress plugins: {len(wp_plugin_results)} checked, {wp_plugin_outdated} outdated")
    for wp_root, slug, installed, latest, outdated in wp_plugin_results:
        if outdated:
            print(f"OUTDATED\t{wp_root}\t{slug}\t{installed}\t(latest: {latest})")

    print(f"# WordPress themes: {len(wp_theme_results)} checked, {wp_theme_outdated} outdated")
    for wp_root, slug, installed, latest, outdated in wp_theme_results:
        if outdated:
            print(f"OUTDATED\t{wp_root}\t{slug}\t{installed}\t(latest: {latest})")

    print(f"# Revive Adserver: {len(revive_results)} install(s), {revive_outdated} outdated")
    for install_root, installed, latest, outdated in revive_results:
        if latest is None:
            print(f"UNKNOWN\t{install_root}\t{installed}\t(could not reach {REVIVE_TAGS_URL})")
        elif outdated:
            print(f"OUTDATED\t{install_root}\t{installed}\t(latest: {latest})")
        else:
            print(f"OK\t{install_root}\t{installed}")

    print(f"# Drupal: {len(drupal_results)} install(s), all unsupported (Drupal 7 end of life)")
    for install_root, installed, latest, outdated, _ in drupal_results:
        note = f"(latest 7.x: {latest})" if outdated and latest else ""
        print(f"UNSUPPORTED\t{install_root}\t{installed}\t{note}")

    print(f"# Joomla: {len(joomla_results)} install(s), {joomla_flagged} flagged")
    for install_root, installed, latest, outdated, branch_unsupported in joomla_results:
        if branch_unsupported:
            print(f"UNSUPPORTED\t{install_root}\t{installed}\t(latest: {latest})")
        elif outdated:
            print(f"OUTDATED\t{install_root}\t{installed}\t(latest: {latest})")
        else:
            print(f"OK\t{install_root}\t{installed}")

    print(f"# Composer packages: {len(composer_results)} checked, {composer_outdated} outdated")
    for lock_path, name, installed, latest, outdated in composer_results:
        if outdated:
            print(f"OUTDATED\t{lock_path}\t{name}\t{installed}\t(latest: {latest})")

    wp_unknown_files = sum(1 for _, _, is_old_leftover in wp_unknown_file_results if not is_old_leftover)
    print(f"# WordPress core: {len(wp_unknown_file_results)} unexpected file(s) under wp-admin/wp-includes, "
          f"{wp_unknown_files} not matching any known release")
    for wp_root, abs_path, is_old_leftover in wp_unknown_file_results:
        tag = "OLD-LEFTOVER" if is_old_leftover else "UNKNOWN"
        print(f"{tag}\t{wp_root}\t{os.path.relpath(abs_path, wp_root)}")

    print(f"# WordPress database content: {len(wp_db_results)} suspicious hit(s) "
          f"(OPENXS_DB_SCAN_ENABLED={os.environ.get('OPENXS_DB_SCAN_ENABLED', '0')})")
    for wp_root, label, rule in wp_db_results:
        print(f"HIT\t{wp_root}\t{label}\t{rule}")

    record_findings(root, wp_results, revive_results, drupal_results, joomla_results,
                     wp_plugin_results, wp_theme_results, composer_results,
                     wp_unknown_file_results, wp_db_results)
    sys.exit(1 if (wp_outdated or revive_outdated or drupal_unsupported or joomla_flagged
                   or wp_plugin_outdated or wp_theme_outdated or composer_outdated
                   or wp_unknown_files or wp_db_results) else 0)


if __name__ == "__main__":
    main()
