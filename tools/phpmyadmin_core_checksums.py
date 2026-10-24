"""Official phpMyAdmin core file checksums, computed from phpmyadmin.net's
own release archive (the "all-languages" zip - matches what a real
install actually has on disk, language packs included). Same reason this
exists as wp_core_checksums.py/drupal_core_checksums.py/
revive_core_checksums.py/roundcube_core_checksums.py: php-malware-finder's
own bundled whitelist is frozen at whatever version it was last generated
against, and phpMyAdmin's own code (it legitimately runs arbitrary SQL)
is a real false-positive source (found live 2026-10-24 on prodserver, our own
DB-admin install)."""
import gzip
import hashlib
import io
import json
import os
import zipfile
import urllib.request

ZIP_URL = "https://files.phpmyadmin.net/phpMyAdmin/{version}/phpMyAdmin-{version}-all-languages.zip"
BUNDLED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phpmyadmin_checksums")


def _bundled_checksums(version):
    """{relative_path: sha256} from tools/phpmyadmin_checksums/<version>.json.gz,
    pre-computed by build_phpmyadmin_checksums_bundle.py and committed to
    the repo. None if this version isn't bundled."""
    path = os.path.join(BUNDLED_DIR, f"{version}.json.gz")
    if not os.path.isfile(path):
        return None
    try:
        with gzip.open(path, "rt") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def compute_checksums_from_zip(version, timeout=30):
    """Downloads phpmyadmin.net's own "all-languages" release zip, hashes
    every file inside it, returns {relative_path: sha256} (paths relative
    to the zip's own top-level "phpMyAdmin-<version>-all-languages/"
    directory - confirmed by hand). None if the download/extraction
    fails."""
    url = ZIP_URL.format(version=version)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
    except Exception:
        return None

    checksums = {}
    prefix = f"phpMyAdmin-{version}-all-languages/"
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


def fetch_checksums(version):
    """{relative_path: sha256} for this exact phpMyAdmin version, bundle
    first (no network), falling back to downloading+hashing the real
    release zip (only happens for a version released after the bundle
    was last updated)."""
    bundled = _bundled_checksums(version)
    if bundled is not None:
        return bundled
    return compute_checksums_from_zip(version)


def file_sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def is_unmodified_core_file(fname, phpmyadmin_root, checksums):
    """True if fname (an absolute path under phpmyadmin_root) matches its
    phpMyAdmin version's official checksum for that relative path."""
    rel = os.path.relpath(fname, phpmyadmin_root)
    expected = checksums.get(rel)
    if expected is None:
        return False
    return file_sha256(fname) == expected
