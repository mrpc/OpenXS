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

def load_ignore_patterns(path):
    """cxs's ignore file: one substring/path per line to skip scanning, or
    'md5:<hash>'/'sha256:<hash>' to ignore by exact file content instead
    (survives a file being renamed/moved, unlike a path-based entry), or
    'regex:<pattern>' for a path pattern too broad for a plain substring
    (e.g. anchored at the start, or with alternation) - added for
    migrate_from_cxs.py's sake, which otherwise had no lossless way to
    carry over cxs's own regex-based ignore entries (pdir:/pfile:/psym:/
    puser:/match:), compiled once here rather than per-file."""
    plain, md5s, sha256s, regexes = [], set(), set(), []
    if path and os.path.isfile(path):
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
    return plain, md5s, sha256s, regexes

def file_hashes(fname, max_size=5 * 1024 * 1024):
    """Real production incident: called unconditionally from is_ignored()
    with no size check at all (unlike the YARA/custom-rules/ClamAV path,
    which has always capped at max_size before ever touching a file's
    content) - a single f.read() with no size argument reads until EOF,
    and if the file is being actively, heavily appended to while we're
    mid-read (an unrotated PHP error log in a tight error-logging loop,
    found for real on balrog), the read can keep extending right along
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


def categorize(rule_name):
    """cxs quarantines only a conservative default (Viruses + Known
    Exploits) 'to avoid otherwise breaking web sites' - filesystem
    indicators (SUID/symlinks/binaries) are much more likely to be a
    legitimate part of the server, so they get their own category."""
    if rule_name.endswith("(ClamAV)"):
        return "virus"
    if rule_name.endswith("(maldet)"):
        return "maldet"
    if rule_name.endswith("(oldversion)"):
        return "oldversion"
    if rule_name in FS_RULES:
        return "fs"
    return "yara"

def load_custom_rules(path):
    """cxs's rule/xtra file: extra regexes to flag, or 'md5:<hash>'/
    'sha256:<hash>' to flag an exact known-exploit file by content hash
    (cxs's --xtra md5sum:/sha256: entries)."""
    patterns, md5s, sha256s = [], {}, {}
    if path and os.path.isfile(path):
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
    with open(filelist_path) as f:
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
        for fname in iter_files(filelist_path, ignore_patterns, changed_hours,
                                 path_overrides=path_overrides, global_fast_php_only=global_fast_php_only):
            if vmrss_max_kb and vmrss_kb() > vmrss_max_kb:
                print(f"# Aborted: VmRSS exceeded {vmrss_max_kb}kB (OPENXS_VMRSS_MAX_KB) after {total} file(s)", file=sys.stderr)
                aborted = True
                break
            total += 1
            scanned_files.append(fname)
            matches = rules.match(fname, fast=True)
            real = [m for m in matches if m.rule != "IsWhitelisted" and m.rule != "IsPhp"]
            custom_hits = check_custom_rules(fname, custom_rules)
            # Scan inside zip/tar archives too (cxs's --options Z) - a
            # webshell uploaded inside a zip would otherwise never be seen,
            # since the archive's own bytes don't contain a <?php tag.
            archive_hits = []
            if fname.endswith(ARCHIVE_EXTS):
                for member_name, data in iter_archive_members(fname):
                    for m in rules.match(data=data):
                        if m.rule not in ("IsWhitelisted", "IsPhp"):
                            archive_hits.append(f"{m.rule} (in archive member {member_name})")
            if real or custom_hits or archive_hits:
                for rule_name in [m.rule for m in real] + custom_hits + archive_hits:
                    print(f"{fname}\t{rule_name}")
                    findings.append((fname, rule_name))
                hits += 1
        t_yara_done = time.perf_counter()
        clam_findings = clamav_scan(scanned_files)
        t_clamav_done = time.perf_counter()
        already_flagged = {f for f, _ in findings}
        for fname, sig in clam_findings:
            print(f"{fname}\t{sig} (ClamAV)")
            findings.append((fname, f"{sig} (ClamAV)"))
            if fname not in already_flagged:
                hits += 1
                already_flagged.add(fname)

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

            if findings:
                # cxs's own default: only quarantine Viruses and Known
                # Exploits, "to avoid otherwise breaking web sites" -
                # filesystem indicators (SUID/symlinks/binaries) are much
                # more likely to be legitimate, so they're opt-in. Each
                # finding's path can override both whether quarantine is
                # on at all and which categories, via path_overrides.
                global_enabled = os.environ.get("OPENXS_QUARANTINE_ENABLED", "0")
                global_cats = os.environ.get("OPENXS_QUARANTINE_CATEGORIES", "virus,yara,maldet")
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
