"""Official Roundcube Webmail core file checksums, computed from GitHub's
own release assets (the "complete" tarball, which includes vendored
dependencies - matches what a real install actually has on disk, unlike
the plain source tarball). Same reason this exists as
wp_core_checksums.py/drupal_core_checksums.py/revive_core_checksums.py:
php-malware-finder's own bundled whitelist is frozen at whatever version
it was last generated against, and Roundcube's own minified JS/obfuscated-
looking vendored libraries are a real false-positive source (found live
2026-10-24 on prod-host-3, our own webmail install)."""
import gzip
import hashlib
import io
import json
import os
import tarfile
import urllib.request

TARBALL_URL = "https://github.com/roundcube/roundcubemail/releases/download/{version}/roundcubemail-{version}-complete.tar.gz"
BUNDLED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "roundcube_checksums")


def _bundled_checksums(version):
    """{relative_path: sha256} from tools/roundcube_checksums/<version>.json.gz,
    pre-computed by build_roundcube_checksums_bundle.py and committed to
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
    """Downloads GitHub's "complete" release asset for this version,
    hashes every file inside it, returns {relative_path: sha256} (paths
    relative to the tarball's own top-level "roundcubemail-<version>/"
    directory - confirmed by hand: the 1.3.1 release asset extracts to
    "roundcubemail-1.3.1/", no 'v' prefix). None if the download/
    extraction fails."""
    url = TARBALL_URL.format(version=version)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
    except Exception:
        return None

    checksums = {}
    prefix = f"roundcubemail-{version}/"
    try:
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


def fetch_checksums(version):
    """{relative_path: sha256} for this exact Roundcube version, bundle
    first (no network), falling back to downloading+hashing the real
    release asset (only happens for a version released after the bundle
    was last updated)."""
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


def is_unmodified_core_file(fname, roundcube_root, checksums):
    """True if fname (an absolute path under roundcube_root) matches its
    Roundcube version's official checksum for that relative path."""
    rel = os.path.relpath(fname, roundcube_root)
    expected = checksums.get(rel)
    if expected is None:
        return False
    return file_sha256(fname) == expected
