#!/usr/bin/env python3
"""
Small wrapper around the compiled php-malware-finder ruleset (php.yar + whitelist.yar)
that works against a list of files (e.g. from `find`) instead of os.walk over an entire
directory tree (public_html also contains uploads/media that we don't want to scan).

Modes:
  whitelist <php.yar> <filelist.txt>  -> prints a YARA rule "Custom" with the SHA1
                                         hashes of files that already match (false
                                         positives on known/current code), same logic
                                         as upstream's utils/generate_whitelist.py but
                                         driven by a file list.
  scan <php.yar> <filelist.txt>       -> prints one line per genuine hit (after
                                         IsWhitelisted suppression): path<TAB>rule
"""
import sys
import os
import re
import shutil
import subprocess
import hashlib
import time
import json
import signal

DEFAULT_IGNORE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "default_ignore")

def _load_ignore_file(path, plain, md5s, sha256s, regexes):
    if not path or not os.path.isfile(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("md5:"):
                md5s.add(line[4:].strip().lower())
            elif line.startswith("sha256:"):
                sha256s.add(line[7:].strip().lower())
            elif line.startswith("regex:"):
                try:
                    regexes.append(re.compile(line[6:].strip()))
                except re.error as e:
                    print(f"# Ignoring invalid regex ignore entry '{line}': {e}", file=sys.stderr)
            else:
                plain.append(line)

def load_ignore_patterns(path):
    """cxs's ignore file: one substring/path per line to skip scanning, or
    'md5:<hash>'/'sha256:<hash>' to ignore by exact file content instead
    (survives a file being renamed/moved, unlike a path-based entry), or
    'regex:<pattern>' for a path pattern too broad for a plain substring
    (e.g. anchored at the start, or with alternation) - added for
    migrate_from_cxs.py's sake, which otherwise had no lossless way to
    carry over cxs's own regex-based ignore entries (pdir:/pfile:/psym:/
    puser:/match:), compiled once here rather than per-file.

    Also always loads default_ignore (shipped alongside this script,
    updated via git pull + install.sh) - false positives on common
    third-party/first-party software that are likely to recur on other
    installs too, not just whatever's in this one server's local,
    user-editable `path`."""
    plain, md5s, sha256s, regexes = [], set(), set(), []
    _load_ignore_file(DEFAULT_IGNORE_FILE, plain, md5s, sha256s, regexes)
    _load_ignore_file(path, plain, md5s, sha256s, regexes)
    return plain, md5s, sha256s, regexes

def file_hashes(fname, max_size=5 * 1024 * 1024):
    """Real production incident: called unconditionally from is_ignored()
    with no size check at all (unlike the YARA/custom-rules/ClamAV path,
    which has always capped at max_size before ever touching a file's
    content) - a single f.read() with no size argument reads until EOF,
    and if the file is being actively, heavily appended to while we're
    mid-read (an unrotated PHP error log in a tight error-logging loop,
    found for real on prodserver), the read can keep extending right along
    with the file's own growth. Took openxs-watchd from ~17MB to over
    1.5GB in under a second, server-wide memory down to under 1GB free
    at one point - not a slow leak, a single read() given no limit at
    all. A multi-megabyte file isn't a plausible exploit signature
    match anyway (cxs's own hash-based ignore entries are for known-bad
    shells, which are small), so skipping the check past max_size costs
    nothing real."""
    try:
        if os.path.getsize(fname) > max_size:
            return None, None
        with open(fname, "rb") as f:
            data = f.read(max_size)
    except OSError:
        return None, None
    return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()

def is_ignored(fname, ignore_patterns, md5s, sha256s, regexes=()):
    if any(p in fname for p in ignore_patterns):
        return True
    if any(r.search(fname) for r in regexes):
        return True
    if md5s or sha256s:
        md5, sha256 = file_hashes(fname)
        if md5 in md5s or sha256 in sha256s:
            return True
    return False

def load_path_overrides(path):
    """Per-path setting overrides - cxs-style 'different settings for this
    folder'. One line per override: '<path-prefix> key=value,key=value',
    e.g. '/home/bigsite/uploads fast_php_only=1'. When several prefixes
    match a file, the longest (most specific) one wins."""
    overrides = []
    if not path or not os.path.isfile(path):
        return overrides
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            prefix, kv = parts
            settings = dict(p.split("=", 1) for p in kv.split(",") if "=" in p)
            overrides.append((prefix, settings))
    overrides.sort(key=lambda o: -len(o[0]))
    return overrides

def effective_setting(fname, overrides, key, default):
    for prefix, settings in overrides:
        if fname.startswith(prefix) and key in settings:
            return settings[key]
    return default

def throttle(max_load):
    """cxs's --throttle: sleep while the 1-minute load average is too high,
    instead of piling more scan work onto an already-busy server."""
    if not max_load:
        return
    try:
        max_load = float(max_load)
    except ValueError:
        return
    while os.getloadavg()[0] > max_load:
        time.sleep(60)

FS_RULES = {"SUID file", "world-writable directory", "symlink", "socket",
            "core dump file", "Linux binary or executable file",
            "Windows binary or executable file", "hidden directory owned by nobody"}

QUARANTINE_LOG = "/var/log/openxs-quarantine.log"

# A rule's own YARA 'score' meta (upstream's confidence rating) doesn't
# correlate well with how noisy it actually is on this fleet (e.g.
# WEBSHELL_PHP_Generic_Callback scores lower than several rules found
# far less prone to false-positiving in practice) - so this is a hand-
# curated, fleet-specific list instead, built up as we find a rule's
# real-world hit rate. Level 1 (default) is every rule not listed here;
# level 2 is "we've confirmed this one hits legitimate common software
# a lot - only report it if OPENXS_YARA_PARANOIA_LEVEL >= 2". Not 4
# levels like mod_security's CRS paranoia (that's curated per-rule by
# the CRS project itself, across thousands of rules - we don't have
# that depth of curation here); add level 3/4 buckets if/when a level
# 2 rule turns out to need even narrower opt-in.
RULE_PARANOIA_LEVEL = {
    "WEBSHELL_PHP_Generic_Callback": 2,
    "EXT_WEBSHELL_PHP_Generic": 2,
    "WEBSHELL_PHP_Dynamic_Big": 2,
}

def paranoia_level_for(rule_name):
    return RULE_PARANOIA_LEVEL.get(rule_name.split(" (", 1)[0], 1)


def log_quarantine(original_path, quarantine_path, category, rule_name):
    """One line per quarantine action - which file, why, where it went -
    for audit/forensics. The scan's own stderr only ever had a count."""
    line = (f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
            f"{original_path} -> {quarantine_path} ({category}: {rule_name})")
    try:
        with open(QUARANTINE_LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


# Registry of known platforms whose unmodified core files can be
# verified against an official (or officially-derived) checksum, to
# suppress a YARA false positive the same way regardless of platform.
# Adding a platform means adding one entry here, not a whole separate
# cache/directory-walk/is_unmodified_*_file function - find_platform_root_for()
# below does a single shared upward walk checking every platform's
# marker at each directory level, so a new platform costs O(1) more
# marker checks per level, never a second independent traversal of the
# same site's directory tree.
def _is_phpmyadmin_root(d):
    # libraries/classes/Config.php + sql/ alone are too generic to key
    # off safely - composer.json's own package name is the unambiguous
    # signal (confirmed by hand: every phpMyAdmin release ships one).
    if not (os.path.isfile(os.path.join(d, "libraries", "classes", "Config.php"))
            and os.path.isdir(os.path.join(d, "sql"))):
        return False
    try:
        with open(os.path.join(d, "composer.json"), errors="replace") as f:
            return '"phpmyadmin/phpmyadmin"' in f.read()
    except OSError:
        return False

_PLATFORMS = [
    {
        "name": "wordpress",
        "marker": lambda d: os.path.isfile(os.path.join(d, "wp-includes", "version.php")),
        "version_relpath": os.path.join("wp-includes", "version.php"),
        "version_re_attr": "WP_VERSION_RE",
        "checksums_module": "wp_core_checksums",
    },
    {
        "name": "drupal7",
        # bootstrap.inc alone is too generic a filename to key off safely
        "marker": lambda d: (os.path.isfile(os.path.join(d, "includes", "bootstrap.inc"))
                              and os.path.isdir(os.path.join(d, "modules"))
                              and os.path.isdir(os.path.join(d, "sites"))),
        "version_relpath": os.path.join("includes", "bootstrap.inc"),
        "version_re_attr": "DRUPAL_VERSION_RE",
        "checksums_module": "drupal_core_checksums",
    },
    {
        "name": "revive",
        # constants.php alone is too generic a filename to key off
        # safely - also requires adview.php, same marker as
        # version_scan.py's find_revive_installs().
        "marker": lambda d: (os.path.isfile(os.path.join(d, "constants.php"))
                              and os.path.isfile(os.path.join(d, "adview.php"))),
        "version_relpath": "constants.php",
        "version_re_attr": "REVIVE_VERSION_RE",
        "checksums_module": "revive_core_checksums",
    },
    {
        "name": "roundcube",
        "marker": lambda d: (os.path.isfile(os.path.join(d, "program", "include", "iniset.php"))
                              and os.path.isfile(os.path.join(d, "program", "lib", "Roundcube", "rcube.php"))),
        "version_relpath": os.path.join("program", "include", "iniset.php"),
        "version_re_attr": "ROUNDCUBE_VERSION_RE",
        "checksums_module": "roundcube_core_checksums",
    },
    {
        "name": "phpmyadmin",
        "marker": _is_phpmyadmin_root,
        "version_relpath": "composer.json",
        "version_re_attr": "PHPMYADMIN_VERSION_RE",
        "checksums_module": "phpmyadmin_core_checksums",
    },
]

_PLATFORM_ROOT_CACHE = {}


def find_platform_root_for(fname):
    """Nearest ancestor directory of fname that matches one of
    _PLATFORMS' markers. Returns (platform_dict, root) or (None, None).
    Memoized per directory - many flagged files in one scan share the
    same install, and every platform's marker is checked in the same
    walk rather than one walk per platform."""
    d = os.path.dirname(fname)
    checked = []
    while d and d not in ("/", ""):
        if d in _PLATFORM_ROOT_CACHE:
            result = _PLATFORM_ROOT_CACHE[d]
            for c in checked:
                _PLATFORM_ROOT_CACHE[c] = result
            return result
        checked.append(d)
        for platform in _PLATFORMS:
            if platform["marker"](d):
                result = (platform, d)
                for c in checked:
                    _PLATFORM_ROOT_CACHE[c] = result
                return result
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    for c in checked:
        _PLATFORM_ROOT_CACHE[c] = (None, None)
    return (None, None)


def detect_platform_version(platform, root):
    """The installed version string for this already-detected platform
    root (per find_platform_root_for()'s own platform dict), or None if
    its version file is unreadable or doesn't match the expected
    pattern. Pulled out of is_unmodified_core_file() so
    restore_pristine.py can reuse the exact same detection instead of
    re-implementing it."""
    try:
        import version_scan
        version_re = getattr(version_scan, platform["version_re_attr"])
    except ImportError:
        return None
    try:
        with open(os.path.join(root, platform["version_relpath"]), errors="replace") as f:
            m = version_re.search(f.read())
    except OSError:
        return None
    return m.group(1) if m else None


def is_unmodified_core_file(fname):
    """True if fname sits under a detected platform install (WordPress,
    Drupal 7, ...) and matches that exact version's official (or
    officially-derived) checksum - i.e. a YARA hit on it (of any
    category, even a "Known exploit" fingerprint match) is a false
    positive: it's provably stock code, byte for byte, not something a
    webshell could be hiding behind. Supplements php-malware-finder's
    bundled whitelist.yar, which only recognizes whatever versions it
    was last generated against (frozen 2018) and otherwise flags a
    site's own legitimate, up-to-date core files once they fall behind.
    Silently does nothing (returns False) if no known platform is
    installed here, or its checksums can't be found (no outbound
    internet and not in the bundle)."""
    platform, root = find_platform_root_for(fname)
    if not platform:
        return False
    try:
        checksums_module = __import__(platform["checksums_module"])
    except ImportError:
        return False
    version = detect_platform_version(platform, root)
    if not version:
        return False
    checksums = checksums_module.fetch_checksums(version)
    if not checksums:
        return False
    return checksums_module.is_unmodified_core_file(fname, root, checksums)


def find_wp_plugin_root_for(fname):
    """If fname sits under some detected WordPress install's
    wp-content/plugins/<slug>/, returns (wp_root, slug, plugin_root).
    None otherwise (not a WordPress install, or not under plugins/ at
    all - e.g. wp-content/themes/, wp-includes/, which is_unmodified_
    core_file already covers for WP core itself)."""
    platform, wp_root = find_platform_root_for(fname)
    if not platform or platform["name"] != "wordpress":
        return None
    plugins_dir = os.path.join(wp_root, "wp-content", "plugins")
    rel = os.path.relpath(fname, plugins_dir)
    if rel.startswith(".."):
        return None
    slug = rel.split(os.sep)[0]
    return (wp_root, slug, os.path.join(plugins_dir, slug))


def is_unmodified_wp_plugin_file(fname):
    """True if fname sits under a wordpress.org-hosted plugin (any
    plugin, not just a hand-picked few) and matches that exact installed
    version's official checksum - generalizes is_unmodified_core_file()
    (WordPress core only) to the plugin ecosystem, which is where most
    of the real false-positive volume actually comes from (a popular
    plugin's own minified/obfuscated-looking legitimate code). Silently
    returns False for a plugin that isn't on wordpress.org (a commercial
    plugin) or whose exact version can't be fetched."""
    found = find_wp_plugin_root_for(fname)
    if not found:
        return False
    wp_root, slug, plugin_root = found
    try:
        import version_scan
        import wp_plugin_checksums
    except ImportError:
        return False
    version = None
    for s, v in version_scan.find_wp_plugins(wp_root):
        if s == slug:
            version = v
            break
    if not version:
        return False
    checksums = wp_plugin_checksums.fetch_checksums(slug, version)
    if not checksums:
        return False
    return wp_plugin_checksums.is_unmodified_core_file(fname, plugin_root, checksums)


WP_PLUGIN_LANG_FILE_RE = re.compile(r'^(?P<slug>.+)-(?P<locale>[a-z]{2,3}(?:_[A-Z]{2})?(?:_[a-z0-9]+)?)\.l10n\.php$')


def find_wp_plugin_lang_file_for(fname):
    """If fname is a WordPress plugin translation file under the single,
    shared wp-content/languages/plugins/ directory (every plugin's
    translations land there together, not nested under the plugin's own
    folder - why find_wp_plugin_root_for() never covers these), returns
    (wp_root, slug, locale). None otherwise."""
    if "/wp-content/languages/plugins/" not in fname:
        return None
    m = WP_PLUGIN_LANG_FILE_RE.match(os.path.basename(fname))
    if not m:
        return None
    platform, wp_root = find_platform_root_for(fname)
    if not platform or platform["name"] != "wordpress":
        return None
    return (wp_root, m.group("slug"), m.group("locale"))


def is_unmodified_wp_plugin_lang_file(fname):
    """True if fname is a wordpress.org plugin's own official translation
    file for its exact installed version/locale - generalizes
    is_unmodified_wp_plugin_file() to the one case it structurally can't
    reach (translations are versioned and distributed completely
    separately from the plugin's own code, see wp_plugin_lang_checksums.py).
    Non-ASCII translated text (Greek, etc.) trips the generic
    NonPrintableChars/DodgyStrings heuristics just as easily as
    obfuscated code does."""
    found = find_wp_plugin_lang_file_for(fname)
    if not found:
        return False
    wp_root, slug, locale = found
    try:
        import version_scan
        import wp_plugin_lang_checksums
    except ImportError:
        return False
    version = None
    for s, v in version_scan.find_wp_plugins(wp_root):
        if s == slug:
            version = v
            break
    if not version:
        return False
    checksums = wp_plugin_lang_checksums.fetch_checksums(slug, version, locale)
    if not checksums:
        return False
    return wp_plugin_lang_checksums.is_unmodified_core_file(fname, checksums)


_COMPOSER_LOCK_ROOT_CACHE = {}


def find_composer_lock_root_for(fname):
    """Nearest ancestor directory of fname containing a composer.lock,
    or None - same memoized-walk-up shape as find_platform_root_for(),
    but composer.lock isn't a _PLATFORMS entry (a project can have one
    at any depth, with no fixed relationship to a CMS/platform marker,
    and a single lock file governs potentially dozens of independently-
    versioned vendor/ sub-packages rather than one whole-install
    version the way _PLATFORMS' markers do)."""
    d = os.path.dirname(fname)
    checked = []
    while d and d not in ("/", ""):
        if d in _COMPOSER_LOCK_ROOT_CACHE:
            result = _COMPOSER_LOCK_ROOT_CACHE[d]
            for c in checked:
                _COMPOSER_LOCK_ROOT_CACHE[c] = result
            return result
        checked.append(d)
        if os.path.isfile(os.path.join(d, "composer.lock")):
            for c in checked:
                _COMPOSER_LOCK_ROOT_CACHE[c] = d
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    for c in checked:
        _COMPOSER_LOCK_ROOT_CACHE[c] = None
    return None


def find_composer_package_root_for(fname):
    """If fname sits under some project's vendor/<org>/<package>/,
    returns (project_root, "<org>/<package>", package_root). None
    otherwise (not under a composer-managed project, or under vendor/
    but not deep enough to be a real package path, e.g. vendor/autoload.php
    itself or vendor/composer/* which isn't a real Packagist package)."""
    project_root = find_composer_lock_root_for(fname)
    if not project_root:
        return None
    vendor_dir = os.path.join(project_root, "vendor")
    rel = os.path.relpath(fname, vendor_dir)
    if rel.startswith(".."):
        return None
    parts = rel.split(os.sep)
    if len(parts) < 3 or parts[0] == "composer":  # vendor/composer/* is Composer's own metadata, not a package
        return None
    name = f"{parts[0]}/{parts[1]}"
    return (project_root, name, os.path.join(vendor_dir, parts[0], parts[1]))


def is_unmodified_composer_package_file(fname):
    """True if fname sits under a Composer-managed project's vendor/ and
    matches that exact installed package version's official checksum
    (from Packagist's own release archive, see composer_package_checksums.py)
    - generalizes is_unmodified_wp_plugin_file()'s pattern to the
    Composer ecosystem. Found live 2026-10-25/26 to be a real,
    substantial false-positive source on two unrelated servers
    (well-known packages like symfony/* triggering generic obfuscation
    heuristics on their own legitimate, often-dense code). Gated by
    composer_trust.is_trusted() - Packagist does no review of what gets
    published under a package name, so a checksum match alone isn't
    enough trust for an obscure/unreviewed package the way it is for
    wordpress.org/drupal.org's own reviewed directories (see
    composer_trust.py's docstring)."""
    found = find_composer_package_root_for(fname)
    if not found:
        return False
    project_root, name, package_root = found
    try:
        import composer_package_checksums
        import composer_trust
    except ImportError:
        return False
    if not composer_trust.is_trusted(name):
        return False
    entry = composer_package_checksums.lock_entry(os.path.join(project_root, "composer.lock"), name)
    if not entry:
        return False
    version, dist_url, reference = entry
    if not version:
        return False
    # A dev-branch alias (e.g. "dev-main") isn't a stable release - cache
    # by its exact pinned commit instead, since the same alias can point
    # at a different commit later (see lock_entry()'s docstring).
    cache_key = reference if version.startswith("dev-") else version
    checksums = composer_package_checksums.fetch_checksums(name, version, dist_url=dist_url, cache_key=cache_key)
    if not checksums:
        return False
    return composer_package_checksums.is_unmodified_core_file(fname, package_root, checksums)


def categorize(rule_name):
    """cxs quarantines only a conservative default (Viruses + Known
    Exploits) 'to avoid otherwise breaking web sites' - filesystem
    indicators (SUID/symlinks/binaries) are much more likely to be a
    legitimate part of the server, so they get their own category.

    The generic YARA heuristics (ObfuscatedPhp, DodgyPhp, DodgyStrings,
    NonPrintableChars, ...) are split out from the high-confidence
    "Known exploit" fingerprint matches into their own category: they
    rely on php-malware-finder's hash-based CMS whitelist to suppress
    hits on legitimate core files, and that whitelist is frozen at
    whatever WordPress/Drupal/etc. version it was last generated
    against - a site that has since updated its CMS core falls out of
    it and would otherwise get real, unmodified files auto-quarantined.
    """
    if rule_name.endswith("(ClamAV)"):
        return "virus"
    if rule_name.endswith("(maldet)"):
        return "maldet"
    if rule_name.endswith("(oldversion)"):
        return "oldversion"
    if rule_name in FS_RULES:
        return "fs"
    if "Known exploit" in rule_name:
        return "yara_exploit"
    return "yara_heuristic"

DEFAULT_RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "default_rules")

def _load_rules_file(path, patterns, md5s, sha256s):
    if not path or not os.path.isfile(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("md5:"):
                md5s[line[4:].strip().lower()] = line
            elif line.startswith("sha256:"):
                sha256s[line[7:].strip().lower()] = line
            else:
                try:
                    patterns.append(re.compile(line.encode()))
                except re.error:
                    continue

def load_custom_rules(path):
    """cxs's rule/xtra file: extra regexes to flag, or 'md5:<hash>'/
    'sha256:<hash>' to flag an exact known-exploit file by content hash
    (cxs's --xtra md5sum:/sha256: entries).

    Also always loads default_rules (shipped alongside this script,
    updated via git pull + install.sh) - general exploit-kit signatures
    worth detecting on every install, not just whatever's in this one
    server's local, user-editable `path`. Same relationship as
    load_ignore_patterns() has to default_ignore."""
    patterns, md5s, sha256s = [], {}, {}
    _load_rules_file(DEFAULT_RULES_FILE, patterns, md5s, sha256s)
    _load_rules_file(path, patterns, md5s, sha256s)
    return patterns, md5s, sha256s

class _RegexTimeout(Exception):
    pass


def _raise_regex_timeout(signum, frame):
    raise _RegexTimeout()


def _search_with_timeout(pattern, data, fname, seconds=2):
    """A custom rule is a user-supplied regex (hand-written, or migrated
    from cxs's cxs.xtra) - one with nested unbounded quantifiers can hit
    Python re's catastrophic backtracking against the right input and
    run effectively forever, consuming huge amounts of memory as it
    backtracks. Found for real: a migrated cxs.xtra rule
    (array\\(...){2,} shape) against a large, repetitive JSON file took
    openxs-watchd from ~16MB to 12+GB RSS before being killed - one
    pathological file took the whole daemon down with it. signal.alarm
    is main-thread-only, which is fine here - every caller of this
    function runs on the main thread (openxs-watchd's event loop and
    pmf_scan's own CLI scan loop), never the scand's threaded socket
    handler (that only ever runs YARA, a different, C-based matcher)."""
    old_handler = signal.signal(signal.SIGALRM, _raise_regex_timeout)
    try:
        signal.alarm(seconds)
        try:
            return pattern.search(data)
        finally:
            signal.alarm(0)
    except _RegexTimeout:
        print(f"# Custom rule timed out (>{seconds}s) matching {fname} - "
              f"skipped, pattern may need rewriting: {pattern.pattern!r}", file=sys.stderr)
        return None
    finally:
        signal.signal(signal.SIGALRM, old_handler)


def is_valid_utf8_file(fname, max_bytes=2_000_000):
    """True if fname decodes as valid UTF-8 end-to-end - used to suppress
    NonPrintableChars (see its call site) on files whose only
    "non-printable" bytes are legitimately-encoded Unicode punctuation/
    text, not obfuscation. Capped at max_bytes (2MB, comfortably above
    any real source file) rather than reading an arbitrarily large file
    a second time just to decide this."""
    try:
        with open(fname, "rb") as f:
            data = f.read(max_bytes + 1)
    except OSError:
        return False
    if len(data) > max_bytes:
        return False
    try:
        data.decode("utf-8", errors="strict")
        return True
    except UnicodeDecodeError:
        return False


DOCUMENTATION_EXTENSIONS = (".md", ".markdown", ".rst", ".txt")


def is_documentation_file(fname):
    """True if fname's extension marks it as prose/documentation, never
    executed as PHP by any standard web server config regardless of its
    content - see the generic-heuristic suppression at its call site."""
    return fname.lower().endswith(DOCUMENTATION_EXTENSIONS)


def is_probably_binary(data, sniff_bytes=8000):
    """Same heuristic git/grep -I use to decide "binary or text": a NUL
    byte anywhere in the first chunk. php-malware-finder's own ruleset
    gates everything behind a global IsPhp rule that just looks for a
    literal '<?' byte sequence anywhere in the file - a fine heuristic
    for actual text/source files, but a 2-byte sequence is likely to
    turn up by pure chance in any reasonably-sized binary blob (a git
    pack file, .git/index, a compiled binary, an image), which is
    exactly why those were false-positiving as "ObfuscatedPhp"/
    "NonPrintableChars". Deliberately NOT a path-based exclusion (an
    exploit can be planted as a plain-text file anywhere, including
    inside a .git directory) - this only skips the YARA *content*
    heuristics for content that is itself genuinely binary; ClamAV and
    the custom MD5/SHA256/regex rules (check_custom_rules) still see
    every file regardless, since those are meaningful on binary content
    too."""
    return b"\x00" in data[:sniff_bytes]


def check_custom_rules(fname, rules):
    patterns, md5s, sha256s = rules
    if not patterns and not md5s and not sha256s:
        return []
    try:
        with open(fname, "rb") as f:
            data = f.read()
    except OSError:
        return []
    hits = [f"Custom rule: {p.pattern.decode(errors='replace')}"
            for p in patterns if _search_with_timeout(p, data, fname)]
    if md5s or sha256s:
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        if md5 in md5s:
            hits.append("Custom rule: known exploit (md5 match)")
        if sha256 in sha256s:
            hits.append("Custom rule: known exploit (sha256 match)")
    return hits

ARCHIVE_EXTS = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2")
PROGRESS_FILE = os.environ.get("OPENXS_SCAN_PROGRESS_FILE", "/var/lib/openxs/scan_progress")
MAX_ARCHIVE_MEMBERS = 2000  # cheap zip-bomb-by-member-count guard

def iter_archive_members(fname):
    """Yields (member_name, data) for each regular file inside a zip/tar
    archive (cxs's --options Z), skipping oversized members/archives with
    too many entries. In-memory only - members are matched against YARA
    via match(data=...), no extraction to disk needed."""
    import zipfile, tarfile
    try:
        if fname.endswith(".zip"):
            with zipfile.ZipFile(fname) as zf:
                infos = zf.infolist()
                if len(infos) > MAX_ARCHIVE_MEMBERS:
                    return
                for info in infos:
                    if info.is_dir() or info.file_size > 5 * 1024 * 1024:
                        continue
                    try:
                        yield info.filename, zf.read(info)
                    except Exception:
                        continue
        elif fname.endswith(ARCHIVE_EXTS):
            with tarfile.open(fname) as tf:
                members = tf.getmembers()
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    return
                for member in members:
                    if not member.isfile() or member.size > 5 * 1024 * 1024:
                        continue
                    try:
                        f = tf.extractfile(member)
                        if f:
                            yield member.name, f.read()
                    except Exception:
                        continue
    except Exception:
        return

def vmrss_kb():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0

def yara_match_via_daemon(fname, socket_path=None):
    """Queries the already-running openxs-scand for every matching rule on
    fname, instead of compiling (and holding in memory) a second copy of
    the ruleset in whatever process calls this. Returns None (not a result
    - "couldn't check") if the daemon isn't reachable.

    `with` guarantees the socket closes even if connect/sendall/recv
    raises (a real production leak: under CPU contention from another
    process, scand's single-threaded accept loop falls behind and recv()
    times out often - each one used to leak the socket and its kernel
    buffers, since s.close() was never reached on that path)."""
    import socket as socket_mod
    socket_path = socket_path or os.environ.get("OPENXS_SOCKET", "/run/openxs/scan.sock")
    try:
        with socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(socket_path)
            s.sendall(f"ALL {fname}\n".encode())
            response = s.recv(65536).decode(errors="replace").strip()
        return json.loads(response)
    except Exception:
        return None

def clamav_scan(filenames):
    """Runs the given (already-filtered) list of files through clamd (cxs's
    'virusscan' equivalent). Returns a list of (path, signature) tuples.
    Silently returns [] if ClamAV isn't installed/running or the list is
    empty - it's an optional second detector, not a hard requirement."""
    if not shutil.which("clamdscan") or not filenames:
        return []
    import tempfile
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(filenames))
            tmp_path = tf.name
        out = subprocess.run(
            ["clamdscan", "--fdpass", "--no-summary", "--infected",
             f"--file-list={tmp_path}"],
            capture_output=True, text=True, timeout=600,
        ).stdout
    except Exception:
        return []
    finally:
        try:
            os.unlink(tmp_path)
        except (OSError, NameError):
            pass
    findings = []
    for line in out.splitlines():
        m = re.match(r"^(.+): (.+) FOUND$", line)
        if m:
            findings.append((m.group(1), m.group(2)))
    return findings

MALDET_EVENT_LOG = "/usr/local/maldetect/logs/event_log"

def maldet_scan(filenames):
    """Runs the given file list through Linux Malware Detect (maldet) -
    its own independently-maintained signature set (rfxn.com: MD5 exact
    hashes + HEX patterns + its own YARA rules), as a third detector on
    top of php-malware-finder's rules and ClamAV. Returns a list of
    (path, signature) tuples. Silently returns [] if maldet isn't
    installed or the list is empty - optional extra detector, not a
    hard requirement.

    quarantine_hits=0 is forced for this invocation: maldet's own default
    config auto-quarantines hits immediately, which would silently move
    files out from under OpenXS's own (opt-in, categorized) quarantine
    pipeline. Detection here is report-only - OpenXS decides what to do
    with a maldet finding the same way it decides for a YARA/ClamAV one.

    scan_clamscan=0 is also forced: maldet uses ClamAV as its own default
    scan engine when available (conf.maldet's own "scan_clamscan=1"),
    which means every file would get ClamAV-scanned twice in the same
    pass - once by our own clamav_scan() above, once again inside maldet.
    Forcing this off makes maldet use only its own independent MD5/HEX/
    YARA signatures here, since ClamAV coverage is already handled.
    """
    maldet_bin = shutil.which("maldet")
    if not maldet_bin or not filenames:
        return []
    import tempfile
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(filenames))
            tmp_path = tf.name
        out = subprocess.run(
            [maldet_bin, "-co", "quarantine_hits=0,scan_clamscan=0", "-f", tmp_path],
            capture_output=True, text=True, timeout=600,
        ).stdout
    except Exception:
        return []
    finally:
        try:
            os.unlink(tmp_path)
        except (OSError, NameError):
            pass

    m = re.search(r"maldet\((\d+)\):", out)
    if not m:
        return []
    pid_marker = f"maldet({m.group(1)}): {{hit}}"
    findings = []
    try:
        with open(MALDET_EVENT_LOG) as f:
            for line in f:
                if pid_marker not in line:
                    continue
                hm = re.search(r"malware hit (\S+) found for (.+?)\s*$", line)
                if hm:
                    findings.append((hm.group(2), hm.group(1)))
    except OSError:
        pass
    return findings

def iter_files(filelist_path, ignore, changed_hours=None, max_size=None,
                path_overrides=None, global_fast_php_only="0"):
    max_size = max_size or 5 * 1024 * 1024
    changed_cutoff = time.time() - float(changed_hours) * 3600 if changed_hours else None
    path_overrides = path_overrides or []
    plain, md5s, sha256s, regexes = ignore
    with open(filelist_path, errors="surrogateescape") as f:
        for line in f:
            fname = line.rstrip("\n")
            if not fname:
                continue
            if is_ignored(fname, plain, md5s, sha256s, regexes):
                continue
            # Per-path "fast mode" override: a specific heavy directory can
            # be narrowed to *.php-only even while the scan as a whole
            # covers everything (the usual, and more useful, direction -
            # going the other way is a no-op since find() never listed
            # the file to begin with when the global scan is php-only).
            fast = effective_setting(fname, path_overrides, "fast_php_only", global_fast_php_only)
            if fast == "1" and not fname.endswith(".php"):
                continue
            try:
                st = os.stat(fname)
            except OSError:
                continue
            if not (0 < st.st_size < max_size):
                continue
            if changed_cutoff and st.st_mtime < changed_cutoff:
                continue
            yield fname

def compile_ruleset(yar_path):
    """php.yar plus our own rules (openxs-rules/*.yar, next to php.yar) -
    real malware families found missing from php-malware-finder's own
    ruleset during OpenXS's corpus analysis, see OpenXS-ops/TIMELINE.md,
    2026-10-22. Shared by every consumer (CLI scans, the scan daemon, the
    watch daemon) so there's exactly one compiled copy of the full
    ruleset, not one per process."""
    import yara
    sources = {"php": yar_path}
    rules_dir = os.path.join(os.path.dirname(os.path.abspath(yar_path)), "openxs-rules")
    if os.path.isdir(rules_dir):
        for fn in sorted(os.listdir(rules_dir)):
            if fn.endswith(".yar"):
                sources[f"openxs_{fn[:-4]}"] = os.path.join(rules_dir, fn)
    return yara.compile(filepaths=sources, includes=True, error_on_warning=False)

def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("whitelist", "scan"):
        print(f"Usage: {sys.argv[0]} whitelist|scan <php.yar> <filelist.txt>", file=sys.stderr)
        sys.exit(1)

    mode, yar_path, filelist_path = sys.argv[1], sys.argv[2], sys.argv[3]
    rules = compile_ruleset(yar_path)

    ignore_patterns = load_ignore_patterns(os.environ.get("OPENXS_IGNORE_FILE", "/etc/openxs/ignore"))
    paranoia_level = int(os.environ.get("OPENXS_YARA_PARANOIA_LEVEL") or 1)
    changed_hours = os.environ.get("OPENXS_CHANGED_HOURS")
    quiet = os.environ.get("OPENXS_QUIET") == "1"
    throttle(os.environ.get("OPENXS_THROTTLE_LOAD"))
    custom_rules = load_custom_rules(os.environ.get("OPENXS_RULE_FILE", "/etc/openxs/rules"))
    path_overrides = load_path_overrides(os.environ.get("OPENXS_PATH_SETTINGS", "/etc/openxs/path_settings"))
    global_fast_php_only = os.environ.get("OPENXS_FAST_PHP_ONLY", "0")
    vmrss_max_kb = int(os.environ.get("OPENXS_VMRSS_MAX_KB", "2000000"))
    aborted = False

    if mode == "whitelist":
        entries = []
        for fname in iter_files(filelist_path, ignore_patterns, changed_hours,
                                 path_overrides=path_overrides, global_fast_php_only=global_fast_php_only):
            matches = rules.match(fname, fast=True)
            if matches:
                with open(fname, "rb") as fh:
                    h = hashlib.sha1(fh.read()).hexdigest()
                entries.append(f'hash.sha1(0, filesize) == "{h}" or // {fname}')
        print('import "hash"\n')
        print("private rule Custom\n{\n    condition:")
        for e in entries:
            print(f"        {e}")
        print("        false\n}")
        print(f"# {len(entries)} files whitelisted", file=sys.stderr)
    else:
        total = 0
        hits = 0
        findings = []
        scanned_files = []
        t_start = time.perf_counter()
        last_progress_write = 0.0
        try:
            os.makedirs(os.path.dirname(PROGRESS_FILE), exist_ok=True)
        except OSError:
            pass
        for fname in iter_files(filelist_path, ignore_patterns, changed_hours,
                                 path_overrides=path_overrides, global_fast_php_only=global_fast_php_only):
            if vmrss_max_kb and vmrss_kb() > vmrss_max_kb:
                print(f"# Aborted: VmRSS exceeded {vmrss_max_kb}kB (OPENXS_VMRSS_MAX_KB) after {total} file(s)", file=sys.stderr)
                aborted = True
                break
            now = time.perf_counter()
            if now - last_progress_write > 2:
                # Lets the dashboard show a completion percentage (against
                # filelist.txt's own line count) and "scanning N of M" -
                # at most every 2s, so this never meaningfully slows down
                # a scan of millions of tiny files.
                try:
                    with open(PROGRESS_FILE, "w") as pf:
                        pf.write(f"scan\t{total}")
                except OSError:
                    pass
                last_progress_write = now
            total += 1
            scanned_files.append(fname)
            try:
                with open(fname, "rb") as f:
                    sniff = f.read(8000)
            except OSError:
                sniff = b""
            if is_probably_binary(sniff):
                # Genuinely binary content (a NUL byte in the first
                # chunk) - skip the YARA text-content ruleset (its
                # IsPhp gate false-positives on binary data, see
                # is_probably_binary()'s docstring), but still run
                # custom_hits/ClamAV below, same as any other file.
                matches = []
            else:
                try:
                    matches = rules.match(fname, fast=True)
                except UnicodeEncodeError:
                    # A path with a raw non-UTF8 byte (surrogateescape'd
                    # by iter_files) can't be passed through to yara's C
                    # extension as a filepath string - but the file
                    # still needs scanning (a webshell doesn't stop
                    # being one for having an oddly-encoded name).
                    # Python's own open() handles a surrogateescape'd
                    # path fine, so read the bytes ourselves and match
                    # against those instead.
                    try:
                        with open(fname, "rb") as f:
                            data = f.read()
                        matches = rules.match(data=data, fast=True)
                    except OSError:
                        print(f"# Skipped (unreadable, unencodable path): {fname!r}", file=sys.stderr)
                        continue
            real = [m for m in matches if m.rule != "IsWhitelisted" and m.rule != "IsPhp"
                    and paranoia_level_for(m.rule) <= paranoia_level]
            if any(m.rule == "NonPrintableChars" for m in real) and is_valid_utf8_file(fname):
                # NonPrintableChars matches 3+ consecutive bytes outside
                # the printable-ASCII range near "function"/"return"/
                # "base64_decode" - a single em dash, curly quote, or any
                # other non-ASCII character in a PHPDoc comment encodes
                # as exactly that in UTF-8 (an em dash is \xe2\x80\x94),
                # and "function"/"return" are two of the most common
                # words in any PHP file. Found live 2026-10-25/26 on two
                # unrelated servers: every one of 521 (prodserver) and 507
                # (newserver.anotherserver) distinct NonPrintableChars-flagged
                # files checked were valid UTF-8 end-to-end - not a
                # handful of edge cases, this was ~98-100% of the
                # category's entire false-positive volume on both. A
                # genuinely obfuscated/binary-packed payload essentially
                # never happens to decode as valid UTF-8 across its whole
                # length, so this only suppresses the rule for content
                # that's provably printable Unicode text, not for
                # anything that could plausibly be hiding a payload.
                # Other rules (ObfuscatedPhp, DangerousPhp, ...) aren't
                # touched - their own trigger patterns don't share this
                # specific "any UTF-8 punctuation is 'non-printable'"
                # false-positive mechanism.
                real = [m for m in real if m.rule != "NonPrintableChars"]
            if real and is_documentation_file(fname):
                # Found live 2026-10-26: a project's own markdown changelog
                # (FRAMEWORK_FINDINGS.md) repeatedly triggering DodgyStrings/
                # DangerousPhp/NonPrintableChars - not malicious, just prose
                # and code-block *examples* discussing real function names
                # (passthru(), exec()) as part of normal engineering
                # documentation, re-triggering on every edit via the
                # real-time watch hook. A .md/.txt/.rst file is never
                # executed as PHP by any standard web server config, so the
                # generic obfuscation-shape heuristics (yara_heuristic) have
                # no webshell to actually catch there - unlike a high-
                # confidence "Known exploit" fingerprint match (yara_exploit)
                # or a virus/maldet signature, which could still legitimately
                # appear verbatim in a doc (e.g. a sample write-up) and stay
                # worth flagging regardless of extension.
                real = [m for m in real if categorize(m.rule) != "yara_heuristic"]
            if real and (is_unmodified_core_file(fname) or is_unmodified_wp_plugin_file(fname)
                         or is_unmodified_wp_plugin_lang_file(fname)
                         or is_unmodified_composer_package_file(fname)):
                # Byte-for-byte matches the official checksum for this
                # exact version (core platform, a wordpress.org-hosted
                # plugin, or that plugin's own official translation
                # file) - whatever rule just matched is a false
                # positive, not something a webshell could be hiding
                # behind. See is_unmodified_wordpress_core_file()'s
                # docstring for why php-malware-finder's own bundled
                # whitelist doesn't already catch this.
                real = []
            custom_hits = check_custom_rules(fname, custom_rules)
            # Scan inside zip/tar archives too (cxs's --options Z) - a
            # webshell uploaded inside a zip would otherwise never be seen,
            # since the archive's own bytes don't contain a <?php tag.
            archive_hits = []
            if fname.endswith(ARCHIVE_EXTS):
                for member_name, data in iter_archive_members(fname):
                    for m in rules.match(data=data):
                        if m.rule not in ("IsWhitelisted", "IsPhp") and paranoia_level_for(m.rule) <= paranoia_level:
                            archive_hits.append(f"{m.rule} (in archive member {member_name})")
            if real or custom_hits or archive_hits:
                for rule_name in [m.rule for m in real] + custom_hits + archive_hits:
                    print(f"{fname}\t{rule_name}")
                    findings.append((fname, rule_name))
                hits += 1
        t_yara_done = time.perf_counter()
        try:
            with open(PROGRESS_FILE, "w") as pf:
                pf.write("clamav\t0")
        except OSError:
            pass
        print(f"# Running ClamAV on {len(scanned_files)} flagged files...", file=sys.stderr)
        clam_findings = clamav_scan(scanned_files)
        print(f"# ClamAV done, {len(clam_findings)} additional hit(s)", file=sys.stderr)
        t_clamav_done = time.perf_counter()
        already_flagged = {f for f, _ in findings}
        for fname, sig in clam_findings:
            print(f"{fname}\t{sig} (ClamAV)")
            findings.append((fname, f"{sig} (ClamAV)"))
            if fname not in already_flagged:
                hits += 1
                already_flagged.add(fname)

        # No per-file progress for maldet/fs below (maldet is one opaque
        # subprocess call over the whole file list; fs_scan walks its own
        # tree independently of this loop's own file list) - at least the
        # STAGE itself is visible now, instead of the dashboard/live log
        # showing nothing at all once ClamAV finishes while the scan is
        # still very much running (maldet and fs_scan can both be slower
        # than YARA+ClamAV combined on a large server).
        try:
            with open(PROGRESS_FILE, "w") as pf:
                pf.write("maldet\t0")
        except OSError:
            pass
        maldet_findings = maldet_scan(scanned_files)
        t_maldet_done = time.perf_counter()
        for fname, sig in maldet_findings:
            print(f"{fname}\t{sig} (maldet)")
            findings.append((fname, f"{sig} (maldet)"))
            if fname not in already_flagged:
                hits += 1
                already_flagged.add(fname)

        # Filesystem-level compromise indicators (SUID files, world-writable
        # dirs, symlinks, sockets, core dumps, stray binaries) - content-
        # agnostic checks that don't go through YARA/ClamAV at all.
        try:
            with open(PROGRESS_FILE, "w") as pf:
                pf.write("fs\t0")
        except OSError:
            pass
        scan_root = os.environ.get("OPENXS_SCAN_LABEL")
        fs_findings = []
        if scan_root and os.path.isdir(scan_root):
            import fs_scan
            fs_findings = [(p, r) for p, r in fs_scan.scan(scan_root)
                           if not is_ignored(p, *ignore_patterns)]
        for fname, rule in fs_findings:
            print(f"{fname}\t{rule}")
            findings.append((fname, rule))
            if fname not in already_flagged:
                hits += 1
                already_flagged.add(fname)
        try:
            os.remove(PROGRESS_FILE)
        except OSError:
            pass
        t_done = time.perf_counter()

        # Per-phase breakdown, not just a total - "is it optimized" needs
        # to know WHICH detector is actually the bottleneck, not just how
        # long the whole scan took. load average is cheap context for the
        # same question (slow scan because of this host, or genuinely a
        # lot of files/a slow detector).
        duration = t_done - t_start
        yara_s, clamav_s, maldet_s, fs_s = (t_yara_done - t_start, t_clamav_done - t_yara_done,
                                             t_maldet_done - t_clamav_done, t_done - t_maldet_done)
        try:
            load_avg = os.getloadavg()[0]
        except OSError:
            load_avg = None

        if not quiet:
            if total == 0 and not clam_findings and not fs_findings:
                print("# Nothing to scan: the given path(s) contained no files.", file=sys.stderr)
            else:
                clam_note = f", {len(clam_findings)} ClamAV hit(s)" if shutil.which("clamdscan") else ""
                abort_note = " (ABORTED early, see VmRSS message above)" if aborted else ""
                print(f"# Scanned {total} file(s), {hits} flagged (YARA after whitelist suppression + ClamAV + maldet + filesystem checks){clam_note}{abort_note}", file=sys.stderr)
            load_note = f", load avg {load_avg:.2f}" if load_avg is not None else ""
            print(f"# Timing: {duration:.1f}s total (YARA {yara_s:.1f}s, ClamAV {clamav_s:.1f}s, "
                  f"maldet {maldet_s:.1f}s, fs {fs_s:.1f}s){load_note}", file=sys.stderr)

        try:
            import openxs_db
            label = os.environ.get("OPENXS_SCAN_LABEL", filelist_path)
            scan_id = openxs_db.record_scan(label, total, findings, duration=duration, load_avg=load_avg)

            # Separate file (not scan_results.txt itself) for the email-
            # alert pipeline to prefer for heuristic/fs findings - a
            # legitimate, unchanged file shouldn't nag on every single
            # scheduled scan forever just because it looks obfuscated.
            # scan_results.txt / the Findings DB page still carry every
            # finding regardless, for browsing/audit.
            new_path = os.environ.get("OPENXS_NEW_FINDINGS_FILE", "new_findings.txt")
            try:
                with open(new_path, "w") as nf:
                    for fname, rule_name in openxs_db.new_finding_ids(scan_id):
                        nf.write(f"{fname}\t{rule_name}\n")
            except OSError:
                pass

            if findings:
                # cxs's own default: only quarantine Viruses and Known
                # Exploits, "to avoid otherwise breaking web sites" -
                # filesystem indicators (SUID/symlinks/binaries) are much
                # more likely to be legitimate, so they're opt-in. Each
                # finding's path can override both whether quarantine is
                # on at all and which categories, via path_overrides.
                global_enabled = os.environ.get("OPENXS_QUARANTINE_ENABLED", "0")
                global_cats = os.environ.get("OPENXS_QUARANTINE_CATEGORIES", "virus,yara_exploit,maldet")
                quarantined = 0
                for fid, fpath, rule_name, _ in openxs_db.findings_for_scan(scan_id):
                    q_enabled = effective_setting(fpath, path_overrides, "quarantine_enabled", global_enabled)
                    if q_enabled != "1":
                        continue
                    category = categorize(rule_name)
                    allowed = set(effective_setting(fpath, path_overrides, "quarantine_categories", global_cats).split(","))
                    if category not in allowed:
                        continue
                    q_path = openxs_db.quarantine_file(fid)
                    if q_path:
                        quarantined += 1
                        log_quarantine(fpath, q_path, category, rule_name)
                if quarantined:
                    print(f"# Quarantined {quarantined} file(s)", file=sys.stderr)
        except Exception as e:
            print(f"# (scan history not recorded: {e})", file=sys.stderr)

if __name__ == "__main__":
    main()
