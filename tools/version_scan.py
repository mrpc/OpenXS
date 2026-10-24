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


def record_findings(root, wp_results, revive_results, composer_results):
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
    findings += [(lock_path, f"Outdated package {name}: {installed} (latest: {latest}) (oldversion)")
                 for lock_path, name, installed, latest, outdated in composer_results if outdated]
    if not findings:
        return
    try:
        import openxs_db
        openxs_db.record_scan(root, len(wp_results) + len(revive_results) + len(composer_results), findings)
    except Exception as e:
        print(f"# (version scan history not recorded: {e})", file=sys.stderr)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <root-dir-to-scan>", file=sys.stderr)
        sys.exit(1)
    root = sys.argv[1]

    wp_results = check_wordpress(root)
    revive_results = check_revive(root)
    composer_results = check_composer(root)

    wp_outdated = sum(1 for _, _, _, outdated in wp_results if outdated)
    revive_outdated = sum(1 for _, _, _, outdated in revive_results if outdated)
    composer_outdated = sum(1 for _, _, _, _, outdated in composer_results if outdated)

    print(f"# WordPress: {len(wp_results)} install(s), {wp_outdated} outdated")
    for wp_root, installed, latest, outdated in wp_results:
        if latest is None:
            print(f"UNKNOWN\t{wp_root}\t{installed}\t(could not reach {LATEST_VERSION_URL})")
        elif outdated:
            print(f"OUTDATED\t{wp_root}\t{installed}\t(latest: {latest})")
        else:
            print(f"OK\t{wp_root}\t{installed}")

    print(f"# Revive Adserver: {len(revive_results)} install(s), {revive_outdated} outdated")
    for install_root, installed, latest, outdated in revive_results:
        if latest is None:
            print(f"UNKNOWN\t{install_root}\t{installed}\t(could not reach {REVIVE_TAGS_URL})")
        elif outdated:
            print(f"OUTDATED\t{install_root}\t{installed}\t(latest: {latest})")
        else:
            print(f"OK\t{install_root}\t{installed}")

    print(f"# Composer packages: {len(composer_results)} checked, {composer_outdated} outdated")
    for lock_path, name, installed, latest, outdated in composer_results:
        if outdated:
            print(f"OUTDATED\t{lock_path}\t{name}\t{installed}\t(latest: {latest})")

    record_findings(root, wp_results, revive_results, composer_results)
    sys.exit(1 if (wp_outdated or revive_outdated or composer_outdated) else 0)


if __name__ == "__main__":
    main()
