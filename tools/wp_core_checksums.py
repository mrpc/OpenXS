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


NOISE_FILENAMES = frozenset({"error_log"})

_all_bundled_hashes_cache = None


def _all_bundled_hashes():
    """The union of every md5 across every bundled WordPress version's
    manifest (tools/wp_checksums/*.json.gz) - lets an "unknown" file
    found under wp-admin/wp-includes be told apart from a genuinely
    unexpected one: a file left behind by an incomplete update (its
    content matches SOME older/newer bundled release, just not the
    one actually installed) is far more common and far less
    interesting than one that matches no release at all (see
    find_unknown_core_files()'s docstring). Computed once per process
    and cached - reading/decompressing 393 bundled manifests (as of
    this writing) per WordPress install found in one scan run would
    otherwise add up fast on a fleet with dozens of installs."""
    global _all_bundled_hashes_cache
    if _all_bundled_hashes_cache is not None:
        return _all_bundled_hashes_cache
    hashes = set()
    try:
        names = os.listdir(BUNDLED_DIR)
    except OSError:
        names = []
    for fn in names:
        if not fn.endswith(".json.gz"):
            continue
        try:
            with gzip.open(os.path.join(BUNDLED_DIR, fn), "rt") as f:
                hashes.update(json.load(f).values())
        except (OSError, ValueError):
            continue
    _all_bundled_hashes_cache = hashes
    return hashes


def find_unknown_core_files(wp_root, version):
    """(abs_path, is_old_leftover) for every file under wp-admin/ and
    wp-includes/ that ISN'T part of this WordPress version's own
    official file list - mirrors Wordfence's own "unknown core file"
    check (wordfenceHash.php's checkKnownFileOther(), restricted to
    exactly these two directories there too - NOT wp-content, where
    uploads/cache/etc. legitimately contain all sorts of extra files
    and this check would be pure noise). A file whose own content still
    matches some OTHER WordPress release (is_old_leftover=True) is very
    likely update residue (a hosting/permissions hiccup leaving an old
    file behind, per Wordfence's own description) - LOW severity. One
    that matches no known release at all is the more interesting case -
    could be a plugin that writes its own file directly into core
    (unusual but not unheard of) or something actually planted there -
    HIGH severity. This only flags EXTRA files; an existing core file
    that's been modified in place is is_unmodified_core_file()'s job,
    not this one's.

    []: if this version isn't bundled and couldn't be fetched live
    either - can't tell "extra" from "expected" without the manifest,
    so this never guesses rather than risk flagging the entire
    installation as unknown."""
    checksums = fetch_checksums(version)
    if checksums is None:
        return []
    known_hashes = _all_bundled_hashes()
    results = []
    for subdir in ("wp-admin", "wp-includes"):
        root = os.path.join(wp_root, subdir)
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                if fn in NOISE_FILENAMES:
                    # Found live 2026-10-26: PHP's own log_errors writes
                    # an "error_log" wherever the error happened, with no
                    # path override set - a near-universal shared-hosting
                    # default, not WordPress-related at all, and not
                    # something a webshell would plausibly be disguised
                    # as (no attacker benefit to the exact name "error_log").
                    continue
                fname = os.path.join(dirpath, fn)
                rel = os.path.relpath(fname, wp_root)
                if rel in checksums:
                    continue
                is_old_leftover = file_md5(fname) in known_hashes
                results.append((fname, is_old_leftover))
    return results
