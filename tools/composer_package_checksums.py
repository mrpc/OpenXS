"""Official checksums for any Composer/Packagist-hosted package, computed
from that exact version's own release archive. Generalizes wp_plugin_
checksums.py's pattern (there are too many packages/versions to
pre-bundle, so this caches to disk on first use instead) to the
vendor/ ecosystem - found live 2026-10-25/26 to be a real, substantial
false-positive source on two unrelated servers (symfony/*, spomky-labs/*
and similar well-known, legitimate Composer dependencies triggering
generic obfuscation heuristics on their own code, same shape of problem
WordPress plugins already had before wp_plugin_checksums.py).

Unlike wordpress.org (one fixed download URL pattern, one predictable
top-level directory name), Packagist doesn't host package archives
itself - it only indexes metadata pointing at wherever the package's
own VCS host (almost always GitHub) publishes a release archive, and
that archive's own top-level directory name isn't predictable from the
package name/version either (GitHub's codeload zips use
"<owner>-<repo>-<short-sha>/"). So this is a two-step fetch: Packagist's
own p2 API first (to find the exact version's dist.url), then that URL
(to get the actual files) - and the top-level directory prefix is
detected from the zip's own contents rather than assumed.
"""
import gzip
import hashlib
import io
import json
import os
import zipfile
import urllib.request

PACKAGIST_P2_URL = "https://repo.packagist.org/p2/{name}.json"
CACHE_DIR = os.environ.get("OPENXS_COMPOSER_CHECKSUM_CACHE_DIR", "/var/lib/openxs/composer_package_checksums")

# Packagist proxies dist downloads mostly through the GitHub API
# (api.github.com/repos/.../zipball/...), which has a much lower
# unauthenticated rate limit (60/hour per IP) than the REST API
# generally (5000/hour with a token) - set this if checksum lookups
# start getting rate-limited across a fleet of servers sharing an
# egress IP. Entirely optional; this module works fine without it,
# just more likely to hit a transient rate limit on a cold cache.
GITHUB_TOKEN = os.environ.get("OPENXS_GITHUB_TOKEN")


def _cache_path(name, version):
    # name is "vendor/package" - keep only characters safe for a cache
    # filename, same spirit as wp_plugin_checksums.py's own safe_slug.
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in f"{name}__{version}")
    return os.path.join(CACHE_DIR, f"{safe_name}.json.gz")


def _cached_checksums(name, version):
    path = _cache_path(name, version)
    if not os.path.isfile(path):
        return None
    try:
        with gzip.open(path, "rt") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _find_dist_url(name, version, timeout=10):
    """The exact release archive URL Packagist knows for this package
    version, or None if the package/version isn't found there at all
    (a private/non-Packagist dependency, or a dev-branch "version" that
    was never a tagged release)."""
    url = PACKAGIST_P2_URL.format(name=name)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None
    for entry in data.get("packages", {}).get(name, []):
        if entry.get("version") == version:
            dist = entry.get("dist") or {}
            return dist.get("url")
    return None


def lock_entry(lock_path, name):
    """(version, dist_url, reference) for this exact package as
    composer.lock itself records it - more direct and more precise than
    asking Packagist's p2 API for it, since composer.lock already pins
    the exact dist URL/commit that's actually installed. Covers
    "dev-main"-style branch aliases too (common for an actively
    developed first-party package pinned straight off its own repo),
    which aren't real Packagist releases and have no dist entry in the
    p2 API at all - found live 2026-10-26 checksum-fetching
    mrpc/pramnosframework and vrana/adminer on a real site pinned to
    dev-main, both silently failing via the p2-only path. None if the
    lock can't be read or doesn't list this package."""
    try:
        with open(lock_path, errors="replace") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    for pkg in data.get("packages", []) + data.get("packages-dev", []):
        if pkg.get("name") == name:
            dist = pkg.get("dist") or {}
            return (pkg.get("version"), dist.get("url"), dist.get("reference"))
    return None


def compute_checksums_from_zip(name, version, timeout=30, dist_url=None):
    """Downloads this exact package version's own release archive and
    hashes every file inside it, returns {relative_path: sha256} - paths
    relative to the archive's own single top-level directory, whatever
    that happens to be named. dist_url overrides the normal Packagist
    p2-API lookup when the caller already has a more precise one (e.g.
    from composer.lock itself, via lock_entry() above) - required for a
    dev-branch alias version, which the p2 API doesn't list at all.
    None if the package/version isn't resolvable, or the download/
    extraction fails."""
    dist_url = dist_url or _find_dist_url(name, version, timeout=timeout)
    if not dist_url:
        return None
    req = urllib.request.Request(dist_url)
    if GITHUB_TOKEN and "api.github.com" in dist_url:
        req.add_header("Authorization", f"Bearer {GITHUB_TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except Exception:
        return None

    checksums = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [n for n in zf.namelist() if not n.endswith("/")]
            if not names:
                return None
            # The archive's one top-level dir, whatever GitHub (or
            # another host) named it - not assumed from the package
            # name/version, confirmed by hand to NOT match either.
            prefix = names[0].split("/", 1)[0] + "/"
            for info in zf.infolist():
                if info.is_dir() or not info.filename.startswith(prefix):
                    continue
                rel = info.filename[len(prefix):]
                checksums[rel] = hashlib.sha256(zf.read(info)).hexdigest()
    except zipfile.BadZipFile:
        return None
    return checksums or None


def fetch_checksums(name, version, dist_url=None, cache_key=None):
    """{relative_path: sha256} for this exact "vendor/package" version,
    disk cache first, falling back to the real release archive (via
    dist_url if given, else Packagist's p2 API) and caching the result
    for next time. cache_key overrides the default (name, version)
    cache identity - pass the composer.lock's own commit reference for
    a dev-branch alias version (e.g. "dev-main"), since that alias
    isn't a stable release and the same alias can point at a different
    commit later; a tagged release's version string is already a
    stable identity on its own and never needs this."""
    cache_key = cache_key or version
    cached = _cached_checksums(name, cache_key)
    if cached is not None:
        return cached
    checksums = compute_checksums_from_zip(name, version, dist_url=dist_url)
    if checksums:
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            with gzip.open(_cache_path(name, cache_key), "wt") as f:
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


def is_unmodified_core_file(fname, package_root, checksums):
    """True if fname (an absolute path under package_root, i.e.
    vendor/<name>/) matches this package version's official checksum
    for that relative path. Named is_unmodified_core_file (not
    _package_file) to match the other checksums modules' shared
    interface."""
    rel = os.path.relpath(fname, package_root)
    expected = checksums.get(rel)
    if expected is None:
        return False
    return file_sha256(fname) == expected
