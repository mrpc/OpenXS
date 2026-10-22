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

def load_ignore_patterns(path):
    """cxs's ignore file: one substring/path per line to skip scanning, or
    'md5:<hash>'/'sha256:<hash>' to ignore by exact file content instead
    (survives a file being renamed/moved, unlike a path-based entry)."""
    plain, md5s, sha256s = [], set(), set()
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
                else:
                    plain.append(line)
    return plain, md5s, sha256s

def file_hashes(fname):
    try:
        with open(fname, "rb") as f:
            data = f.read()
    except OSError:
        return None, None
    return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()

def is_ignored(fname, ignore_patterns, md5s, sha256s):
    if any(p in fname for p in ignore_patterns):
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

def categorize(rule_name):
    """cxs quarantines only a conservative default (Viruses + Known
    Exploits) 'to avoid otherwise breaking web sites' - filesystem
    indicators (SUID/symlinks/binaries) are much more likely to be a
    legitimate part of the server, so they get their own category."""
    if rule_name.endswith("(ClamAV)"):
        return "virus"
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

def check_custom_rules(fname, rules):
    patterns, md5s, sha256s = rules
    if not patterns and not md5s and not sha256s:
        return []
    try:
        with open(fname, "rb") as f:
            data = f.read()
    except OSError:
        return []
    hits = [f"Custom rule: {p.pattern.decode(errors='replace')}" for p in patterns if p.search(data)]
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
    - "couldn't check") if the daemon isn't reachable."""
    import socket as socket_mod
    socket_path = socket_path or os.environ.get("OPENXS_SOCKET", "/run/openxs/scan.sock")
    try:
        s = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
        s.settimeout(5)
        s.connect(socket_path)
        s.sendall(f"ALL {fname}\n".encode())
        response = s.recv(65536).decode(errors="replace").strip()
        s.close()
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

def iter_files(filelist_path, ignore, changed_hours=None, max_size=None,
                path_overrides=None, global_fast_php_only="0"):
    max_size = max_size or 5 * 1024 * 1024
    changed_cutoff = time.time() - float(changed_hours) * 3600 if changed_hours else None
    path_overrides = path_overrides or []
    plain, md5s, sha256s = ignore
    with open(filelist_path) as f:
        for line in f:
            fname = line.rstrip("\n")
            if not fname:
                continue
            if is_ignored(fname, plain, md5s, sha256s):
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
        clam_findings = clamav_scan(scanned_files)
        already_flagged = {f for f, _ in findings}
        for fname, sig in clam_findings:
            print(f"{fname}\t{sig} (ClamAV)")
            findings.append((fname, f"{sig} (ClamAV)"))
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

        if not quiet:
            if total == 0 and not clam_findings and not fs_findings:
                print("# Nothing to scan: the given path(s) contained no files.", file=sys.stderr)
            else:
                clam_note = f", {len(clam_findings)} ClamAV hit(s)" if shutil.which("clamdscan") else ""
                abort_note = " (ABORTED early, see VmRSS message above)" if aborted else ""
                print(f"# Scanned {total} file(s), {hits} flagged (YARA after whitelist suppression + ClamAV + filesystem checks){clam_note}{abort_note}", file=sys.stderr)

        try:
            import openxs_db
            label = os.environ.get("OPENXS_SCAN_LABEL", filelist_path)
            scan_id = openxs_db.record_scan(label, total, findings)

            if findings:
                # cxs's own default: only quarantine Viruses and Known
                # Exploits, "to avoid otherwise breaking web sites" -
                # filesystem indicators (SUID/symlinks/binaries) are much
                # more likely to be legitimate, so they're opt-in. Each
                # finding's path can override both whether quarantine is
                # on at all and which categories, via path_overrides.
                global_enabled = os.environ.get("OPENXS_QUARANTINE_ENABLED", "0")
                global_cats = os.environ.get("OPENXS_QUARANTINE_CATEGORIES", "virus,yara")
                quarantined = 0
                for fid, fpath, rule_name, _ in openxs_db.findings_for_scan(scan_id):
                    q_enabled = effective_setting(fpath, path_overrides, "quarantine_enabled", global_enabled)
                    if q_enabled != "1":
                        continue
                    allowed = set(effective_setting(fpath, path_overrides, "quarantine_categories", global_cats).split(","))
                    if categorize(rule_name) in allowed and openxs_db.quarantine_file(fid):
                        quarantined += 1
                if quarantined:
                    print(f"# Quarantined {quarantined} file(s)", file=sys.stderr)
        except Exception as e:
            print(f"# (scan history not recorded: {e})", file=sys.stderr)

if __name__ == "__main__":
    main()
