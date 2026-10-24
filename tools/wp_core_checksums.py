"""Official WordPress core file checksums (wordpress.org), as a live
replacement for php-malware-finder's bundled wordpress.yar whitelist -
that one is a fixed set of hashes frozen at whenever it was last
generated (2018 for the version shipped with our pinned commit), so
any site that has since updated its WordPress core falls out of it and
its perfectly legitimate, unmodified core files start tripping the
generic YARA heuristics (ObfuscatedPhp, DodgyStrings, ...) instead.

https://api.wordpress.org/core/checksums/1.0/?version=X.Y.Z&locale=en_US
returns {"checksums": {"wp-includes/comment.php": "<md5>", ...}} - a
released version's checksums never change, so these are cached
forever once fetched (one row per version, unlike version_scan.py's
latest-version cache which has a TTL since "latest" does change).
"""
import gzip
import hashlib
import json
import os
import sqlite3
import urllib.request

CHECKSUMS_URL = "https://api.wordpress.org/core/checksums/1.0/?version={version}&locale={locale}"
CACHE_DB = os.environ.get("OPENXS_WP_CHECKSUM_CACHE_DB", "/var/lib/openxs/wp_checksums.db")
BUNDLED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wp_checksums")


def _cache_connect():
    os.makedirs(os.path.dirname(CACHE_DB), exist_ok=True)
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("CREATE TABLE IF NOT EXISTS wp_checksums "
                 "(version TEXT PRIMARY KEY, checksums_json TEXT)")
    return conn


def _bundled_checksums(version):
    """{relative_path: md5} from tools/wp_checksums/<version>.json.gz,
    pre-fetched by build_wp_checksums_bundle.py and committed to the
    repo - works with no outbound internet access at all, which some of
    our servers genuinely have none of. None if this version isn't
    bundled (too old, or newer than the last bundle refresh)."""
    path = os.path.join(BUNDLED_DIR, f"{version}.json.gz")
    if not os.path.isfile(path):
        return None
    try:
        with gzip.open(path, "rt") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def fetch_checksums(version, locale="en_US", timeout=5):
    """{relative_path: md5} for this exact WordPress version, or None if
    it isn't bundled and couldn't be fetched live either (unreachable,
    or wordpress.org doesn't know this version - e.g. a pre-release or
    a very old/new one). Checks the bundle first (no network needed,
    works offline); a live fetch is cached forever once it succeeds."""
    bundled = _bundled_checksums(version)
    if bundled is not None:
        return bundled

    conn = _cache_connect()
    row = conn.execute("SELECT checksums_json FROM wp_checksums WHERE version = ?", (version,)).fetchone()
    if row:
        conn.close()
        return json.loads(row[0])

    try:
        url = CHECKSUMS_URL.format(version=version, locale=locale)
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read())
        checksums = data.get("checksums") or None
    except Exception:
        checksums = None

    if checksums is not None:
        conn.execute("INSERT OR REPLACE INTO wp_checksums (version, checksums_json) VALUES (?, ?)",
                     (version, json.dumps(checksums)))
        conn.commit()
    conn.close()
    return checksums


def file_md5(path):
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def is_unmodified_core_file(fname, wp_root, checksums):
    """True if fname (an absolute path under wp_root) matches its
    WordPress version's official checksum for that relative path -
    i.e. it's exactly the stock core file, not something a webshell
    could be hiding behind."""
    rel = os.path.relpath(fname, wp_root)
    expected = checksums.get(rel)
    if expected is None:
        return False
    return file_md5(fname) == expected
