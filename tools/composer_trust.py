"""Whether a Composer/Packagist package is trusted enough for
composer_package_checksums.py's checksum-match suppression to apply at
all - a different, Composer-specific concern from "does this file match
the official release": Packagist does zero review of what gets
published under a package name (pure auto-indexing from any GitHub
repo), unlike wordpress.org/drupal.org which both have an actual
directory review process. A checksum match only proves "matches what
Packagist says is official" - for an unreviewed, obscure/new package
that's a much weaker signal than for an established one, since a
supply-chain-compromised or malicious release would match its own
checksum too.

Gated by OPENXS_YARA_PARANOIA_LEVEL (same setting pmf_scan.py's generic
heuristic suppression already reads):
  1 (default) - tools/composer_trusted_packages prefixes auto-trusted,
    anything else trusted via Packagist's own reputation stats (age +
    downloads, low bar - OPENXS_COMPOSER_TRUST_MIN_AGE_DAYS/
    OPENXS_COMPOSER_TRUST_MIN_DOWNLOADS).
  2 - only tools/composer_trusted_packages prefixes are trusted, via a
    MUCH higher reputation bar for everything else
    (OPENXS_COMPOSER_TRUST_L2_MIN_AGE_DAYS/_L2_MIN_DOWNLOADS) - an
    unknown/low-traffic package no longer gets auto-trusted just for
    having existed 90 days.
  3 - Composer-checksum suppression disabled entirely, regardless of
    whitelist or stats.

Reputation stats are cached (STATS_CACHE_DB, STATS_CACHE_TTL) - a
non-whitelisted package otherwise hits Packagist's info API on every
single one of its files, on every scan, across however many sites on
the fleet install it."""
import fnmatch
import json
import os
import sqlite3
import time
import urllib.request

PACKAGIST_INFO_URL = "https://packagist.org/packages/{name}.json"
WHITELIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "composer_trusted_packages")
STATS_CACHE_DB = os.environ.get("OPENXS_COMPOSER_STATS_CACHE_DB", "/var/lib/openxs/composer_trust_stats.db")
STATS_CACHE_TTL = 7 * 24 * 3600  # downloads/age only matter at a coarse level here - re-check at most once a week


def _load_whitelist(path=WHITELIST_PATH):
    patterns = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    except OSError:
        pass
    return patterns


def is_whitelisted(name, patterns=None):
    patterns = _load_whitelist() if patterns is None else patterns
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def _stats_cache_connect():
    os.makedirs(os.path.dirname(STATS_CACHE_DB), exist_ok=True)
    conn = sqlite3.connect(STATS_CACHE_DB)
    conn.execute("CREATE TABLE IF NOT EXISTS package_stats "
                 "(name TEXT PRIMARY KEY, published_ts REAL, downloads INTEGER, checked_at REAL NOT NULL)")
    return conn


def _package_stats(name, timeout=10):
    """(age_days, total_downloads) from Packagist's own package-info API -
    every non-whitelisted package hit this on every scan before this
    cache existed, which doesn't scale across a whole fleet's worth of
    vendor/ files. published_ts (the package's first-release date) never
    changes once known, so it's cached forever; downloads is re-checked
    at most once a week (STATS_CACHE_TTL) since it only matters here at
    a coarse, slow-changing level. A transient lookup failure falls back
    to a stale cache entry rather than failing closed outright - only a
    cold cache with no successful lookup ever returns None."""
    conn = _stats_cache_connect()
    row = conn.execute("SELECT published_ts, downloads, checked_at FROM package_stats WHERE name = ?",
                        (name,)).fetchone()
    if row and time.time() - row[2] < STATS_CACHE_TTL:
        conn.close()
        return ((time.time() - row[0]) / 86400, row[1])

    url = PACKAGIST_INFO_URL.format(name=name)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read())
        package = data.get("package") or {}
        first_published = package.get("time")
        downloads = (package.get("downloads") or {}).get("total")
        if not first_published or downloads is None:
            raise ValueError("missing time/downloads in Packagist response")
        published_ts = time.mktime(time.strptime(first_published[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        conn.close()
        if row:
            return ((time.time() - row[0]) / 86400, row[1])
        return None

    conn.execute("INSERT INTO package_stats (name, published_ts, downloads, checked_at) VALUES (?, ?, ?, ?) "
                 "ON CONFLICT(name) DO UPDATE SET downloads=excluded.downloads, checked_at=excluded.checked_at",
                 (name, published_ts, downloads, time.time()))
    conn.commit()
    conn.close()
    return ((time.time() - published_ts) / 86400, downloads)


def meets_reputation_bar(name, min_age_days, min_downloads):
    stats = _package_stats(name)
    if stats is None:
        return False
    age_days, downloads = stats
    return age_days >= min_age_days and downloads >= min_downloads


def is_trusted(name, paranoia_level=None):
    """True if this "vendor/package" should be trusted for checksum-
    match suppression, per the current OPENXS_YARA_PARANOIA_LEVEL (or
    paranoia_level if given, mainly for tests)."""
    if paranoia_level is None:
        paranoia_level = int(os.environ.get("OPENXS_YARA_PARANOIA_LEVEL") or 1)

    if paranoia_level >= 3:
        return False
    if is_whitelisted(name):
        return True
    if paranoia_level >= 2:
        min_age = int(os.environ.get("OPENXS_COMPOSER_TRUST_L2_MIN_AGE_DAYS", "180"))
        min_downloads = int(os.environ.get("OPENXS_COMPOSER_TRUST_L2_MIN_DOWNLOADS", "50000"))
    else:
        min_age = int(os.environ.get("OPENXS_COMPOSER_TRUST_MIN_AGE_DAYS", "90"))
        min_downloads = int(os.environ.get("OPENXS_COMPOSER_TRUST_MIN_DOWNLOADS", "1000"))
    return meets_reputation_bar(name, min_age, min_downloads)
