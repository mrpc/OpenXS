"""Official WordPress.org plugin checksums, computed from wordpress.org's
own per-version download zip (the same URL WordPress core's own "install
this version" feature uses - confirmed by hand: downloads.wordpress.org/
plugin/<slug>.<version>.zip, extracting to a top-level "<slug>/" directory,
no version suffix in the directory name). Generalizes wp_core_checksums.py
(WordPress core only) to any plugin hosted on wordpress.org - there are
thousands of plugins and versions, far too many to pre-bundle and commit
like the core/Drupal/Revive/Roundcube/phpMyAdmin bundles, so this caches
to disk on first use per (slug, version) instead - a plugin version's
files never change once released, so the cache never goes stale.

Covers most of the real false-positive volume found live 2026-10-24
(Wordfence, Jetpack, Yoast SEO/wordpress-seo, and others were all
wordpress.org-hosted plugins triggering generic obfuscation heuristics
on their own legitimate, often-minified code) - a commercial/non-wp.org
plugin (e.g. RevSlider) isn't covered by this and needs its own fix."""
import gzip
import hashlib
import io
import json
import os
import zipfile
import urllib.request

DOWNLOAD_URL = "https://downloads.wordpress.org/plugin/{slug}.{version}.zip"
CACHE_DIR = os.environ.get("OPENXS_WP_PLUGIN_CHECKSUM_CACHE_DIR", "/var/lib/openxs/wp_plugin_checksums")


def _cache_path(slug, version):
    # slug is a directory name straight off disk (wp-content/plugins/<slug>)
    # - keep only characters safe for a cache filename, same spirit as
    # quarantine_file()'s safe_name.
    safe_slug = "".join(c if c.isalnum() or c in "-_" else "_" for c in slug)
    return os.path.join(CACHE_DIR, f"{safe_slug}__{version}.json.gz")


def _cached_checksums(slug, version):
    path = _cache_path(slug, version)
    if not os.path.isfile(path):
        return None
    try:
        with gzip.open(path, "rt") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def compute_checksums_from_zip(slug, version, timeout=30):
    """Downloads wordpress.org's own per-version zip for this plugin,
    hashes every file inside it, returns {relative_path: sha256} (paths
    relative to the zip's own top-level "<slug>/" directory). None if
    the download/extraction fails (including a slug/version that simply
    doesn't exist on wordpress.org - a commercial plugin, or a version
    string this plugin doesn't actually use)."""
    url = DOWNLOAD_URL.format(slug=slug, version=version)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
    except Exception:
        return None

    checksums = {}
    prefix = f"{slug}/"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.startswith(prefix):
                    continue
                rel = info.filename[len(prefix):]
                checksums[rel] = hashlib.sha256(zf.read(info)).hexdigest()
    except zipfile.BadZipFile:
        return None
    return checksums or None


def fetch_checksums(slug, version):
    """{relative_path: sha256} for this exact plugin version, disk cache
    first, falling back to downloading+hashing the real release zip and
    caching the result for next time."""
    cached = _cached_checksums(slug, version)
    if cached is not None:
        return cached
    checksums = compute_checksums_from_zip(slug, version)
    if checksums:
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            with gzip.open(_cache_path(slug, version), "wt") as f:
                json.dump(checksums, f)
        except OSError:
            pass
    return checksums


def file_sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def fetch_file_content(slug, version, rel_path, timeout=60):
    """The real, pristine bytes of one file from this plugin version's
    own release zip - used only by the manual "restore to pristine
    version" action (restore_pristine.py), not by anything in the
    regular scan path (which only ever needs the hash, via
    fetch_checksums() above). Downloaded fresh every call - this
    doesn't happen often enough to be worth caching a whole zip's
    content on disk the way fetch_checksums() caches hashes. None if
    the download fails or rel_path isn't in this release."""
    url = DOWNLOAD_URL.format(slug=slug, version=version)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
    except Exception:
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            try:
                return zf.read(f"{slug}/{rel_path}")
            except KeyError:
                return None
    except zipfile.BadZipFile:
        return None


def is_unmodified_core_file(fname, plugin_root, checksums):
    """True if fname (an absolute path under plugin_root) matches this
    plugin version's official checksum for that relative path. Named
    is_unmodified_core_file (not _plugin_file) to match the other
    checksums modules' shared interface, even though "core" here means
    "this plugin's own shipped code", not WordPress core."""
    rel = os.path.relpath(fname, plugin_root)
    expected = checksums.get(rel)
    if expected is None:
        return False
    return file_sha256(fname) == expected
