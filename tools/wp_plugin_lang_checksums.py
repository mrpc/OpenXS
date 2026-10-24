"""Official WordPress.org plugin TRANSLATION file checksums - a plugin's
own release zip (wp_plugin_checksums.py) never contains these at all
(confirmed by hand: downloaded jetpack's own zip, grepped for "languages",
nothing). Translations are versioned and distributed completely
separately, via api.wordpress.org/translations/plugins/1.0/ (one zip per
plugin+version+locale, flat - no "<slug>/" prefix like the plugin's own
zip has), and land in WordPress's own single shared directory
(wp-content/languages/plugins/<slug>-<locale>.l10n.php, alongside every
other plugin's translations, not nested under the plugin's own folder) -
why find_wp_plugin_root_for()/wp_plugin_checksums.py never covered these.
A real false-positive source: non-ASCII (Greek, etc.) translated text
trips NonPrintableChars/DodgyStrings just as easily as obfuscated code
does, found live 2026-10-24 recurring across many unrelated accounts."""
import gzip
import hashlib
import io
import json
import os
import zipfile
import urllib.request

TRANSLATIONS_API = "https://api.wordpress.org/translations/plugins/1.0/?slug={slug}&version={version}"
CACHE_DIR = os.environ.get("OPENXS_WP_PLUGIN_LANG_CACHE_DIR", "/var/lib/openxs/wp_plugin_lang_checksums")


def _cache_path(slug, version, locale):
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in f"{slug}__{version}__{locale}")
    return os.path.join(CACHE_DIR, f"{safe}.json.gz")


def _cached_checksums(slug, version, locale):
    path = _cache_path(slug, version, locale)
    if not os.path.isfile(path):
        return None
    try:
        with gzip.open(path, "rt") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _package_url(slug, version, locale, timeout=15):
    url = TRANSLATIONS_API.format(slug=slug, version=version)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None
    for t in data.get("translations", []):
        if t.get("language") == locale:
            return t.get("package")
    return None


def compute_checksums_from_zip(slug, version, locale, timeout=30):
    """Downloads this plugin+version+locale's translation zip and hashes
    every file inside (flat - no directory prefix, confirmed by hand).
    None if no such translation exists, or the download/extraction
    fails."""
    pkg_url = _package_url(slug, version, locale, timeout=timeout)
    if not pkg_url:
        return None
    try:
        with urllib.request.urlopen(pkg_url, timeout=timeout) as resp:
            data = resp.read()
    except Exception:
        return None

    checksums = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                checksums[info.filename] = hashlib.sha256(zf.read(info)).hexdigest()
    except zipfile.BadZipFile:
        return None
    return checksums or None


def fetch_checksums(slug, version, locale):
    """{filename: sha256} for this exact plugin+version+locale, disk
    cache first, falling back to downloading+hashing the real
    translation zip and caching the result for next time."""
    cached = _cached_checksums(slug, version, locale)
    if cached is not None:
        return cached
    checksums = compute_checksums_from_zip(slug, version, locale)
    if checksums:
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            with gzip.open(_cache_path(slug, version, locale), "wt") as f:
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


def is_unmodified_core_file(fname, checksums):
    """True if fname (a language file, any absolute path - these all
    live flat in one shared directory, not nested per-plugin) matches
    its official checksum. Looked up by basename, not a directory-
    relative path (unlike every other checksums module here) since
    these are flat to begin with."""
    expected = checksums.get(os.path.basename(fname))
    if expected is None:
        return False
    return file_sha256(fname) == expected
