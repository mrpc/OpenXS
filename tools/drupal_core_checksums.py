"""Official Drupal core file checksums, computed by us (Drupal.org has
no per-file checksums API like wordpress.org's - only a whole-tarball
md5) from the real release tarballs, as a live replacement for
php-malware-finder's bundled drupal.yar whitelist - frozen at whatever
version it was last generated against, same gap as wordpress.yar (see
wp_core_checksums.py's docstring).

Drupal 7.x specifically, since that's the only major version actually
found installed across our fleet so far (8+ restructures core into a
Composer-managed layout, a different detection problem entirely - see
version_scan.py's docstring on this).
"""
import gzip
import hashlib
import json
import os
import tarfile
import urllib.request

RELEASE_HISTORY_URL = "https://updates.drupal.org/release-history/drupal/7.x"
TARBALL_URL = "https://ftp.drupal.org/files/projects/drupal-{version}.tar.gz"
CACHE_DB = os.environ.get("OPENXS_DRUPAL_CHECKSUM_CACHE_DB", "/var/lib/openxs/drupal_checksums.db")
BUNDLED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "drupal_checksums")


def _bundled_checksums(version):
    """{relative_path: sha256} from tools/drupal_checksums/<version>.json.gz,
    pre-computed by build_drupal_checksums_bundle.py and committed to
    the repo. None if this version isn't bundled."""
    path = os.path.join(BUNDLED_DIR, f"{version}.json.gz")
    if not os.path.isfile(path):
        return None
    try:
        with gzip.open(path, "rt") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def compute_checksums_from_tarball(version, timeout=30):
    """Downloads the real drupal-<version>.tar.gz, hashes every file
    inside it, returns {relative_path: sha256} (paths relative to the
    tarball's own top-level "drupal-<version>/" directory, matching
    how a real install's files sit relative to its own root). None if
    the download/extraction fails."""
    url = TARBALL_URL.format(version=version)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
    except Exception:
        return None

    checksums = {}
    prefix = f"drupal-{version}/"
    try:
        import io
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for member in tar:
                if not member.isfile() or not member.name.startswith(prefix):
                    continue
                rel = member.name[len(prefix):]
                fh = tar.extractfile(member)
                if fh is None:
                    continue
                checksums[rel] = hashlib.sha256(fh.read()).hexdigest()
    except tarfile.TarError:
        return None
    return checksums or None


def fetch_file_content(version, rel_path, timeout=30):
    """The real, pristine bytes of one file from this Drupal version's
    own release tarball - used only by the manual "restore to pristine
    version" action (restore_pristine.py), not by anything in the
    regular scan path (which only ever needs the hash, via
    fetch_checksums() above). Downloads the tarball fresh every call -
    this doesn't happen often enough to be worth caching a whole
    tarball's content on disk the way fetch_checksums() caches hashes.
    None if the download fails or rel_path isn't in this release."""
    url = TARBALL_URL.format(version=version)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
    except Exception:
        return None
    prefix = f"drupal-{version}/"
    try:
        import io
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            try:
                member = tar.getmember(prefix + rel_path)
            except KeyError:
                return None
            fh = tar.extractfile(member)
            return fh.read() if fh else None
    except tarfile.TarError:
        return None


def fetch_checksums(version):
    """{relative_path: sha256} for this exact Drupal 7.x version, bundle
    first (no network), falling back to downloading+hashing the real
    tarball (heavier than wordpress.org's simple API call - only
    happens for a version released after the bundle was last updated).
    Not cached across calls here; build_drupal_checksums_bundle.py is
    the thing that should be re-run to make a version permanently
    fast, same as the WordPress bundle."""
    bundled = _bundled_checksums(version)
    if bundled is not None:
        return bundled
    return compute_checksums_from_tarball(version)


def file_sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def is_unmodified_core_file(fname, drupal_root, checksums):
    """True if fname (an absolute path under drupal_root) matches its
    Drupal version's official checksum for that relative path."""
    rel = os.path.relpath(fname, drupal_root)
    expected = checksums.get(rel)
    if expected is None:
        return False
    return file_sha256(fname) == expected
