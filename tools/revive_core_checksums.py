"""Official Revive Adserver core file checksums, computed from GitHub's
own tag archives (revive-adserver has no uploaded release assets or
per-file checksums API - confirmed via the GitHub releases API, which
returns none; only git tags exist). Same reason this exists as
wp_core_checksums.py/drupal_core_checksums.py: php-malware-finder's own
bundled whitelist is frozen at whatever version it was last generated
against, and Revive's own delivery scripts (www/delivery/*.php) are
legitimately minified/obfuscated-looking by design (ad-delivery code,
not malware) - a real false-positive source found in production
(ObfuscatedPhp/DodgyPhp on cl.php, ajs.php, al.php, spc.php, etc.)."""
import gzip
import hashlib
import io
import json
import os
import tarfile
import urllib.request

TARBALL_URL = "https://github.com/revive-adserver/revive-adserver/archive/refs/tags/v{version}.tar.gz"
CACHE_DB = os.environ.get("OPENXS_REVIVE_CHECKSUM_CACHE_DB", "/var/lib/openxs/revive_checksums.db")
BUNDLED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "revive_checksums")


def _bundled_checksums(version):
    """{relative_path: sha256} from tools/revive_checksums/<version>.json.gz,
    pre-computed by build_revive_checksums_bundle.py and committed to
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
    """Downloads GitHub's own tag archive for v<version> (no uploaded
    release asset exists - confirmed via the releases API), hashes
    every file inside it, returns {relative_path: sha256} (paths
    relative to the tarball's own top-level "revive-adserver-<version>/"
    directory, matching how a real install's files sit relative to its
    own root - confirmed by hand: the tag "v6.0.8" archive extracts to
    "revive-adserver-6.0.8/", no 'v' prefix in the directory name).
    None if the download/extraction fails."""
    url = TARBALL_URL.format(version=version)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
    except Exception:
        return None

    checksums = {}
    prefix = f"revive-adserver-{version}/"
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
    """{relative_path: sha256} for this exact Revive Adserver version,
    bundle first (no network), falling back to downloading+hashing the
    real tag archive (only happens for a version released after the
    bundle was last updated)."""
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


def is_unmodified_core_file(fname, revive_root, checksums):
    """True if fname (an absolute path under revive_root) matches its
    Revive Adserver version's official checksum for that relative path."""
    rel = os.path.relpath(fname, revive_root)
    expected = checksums.get(rel)
    if expected is None:
        return False
    return file_sha256(fname) == expected
