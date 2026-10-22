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

def load_ignore_patterns(path):
    """cxs's ignore file: one substring/path per line to skip scanning."""
    if not path or not os.path.isfile(path):
        return []
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

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
    """cxs's rule file: extra regexes to flag, beyond the built-in ruleset."""
    if not path or not os.path.isfile(path):
        return []
    patterns = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                patterns.append(re.compile(line.encode()))
            except re.error:
                continue
    return patterns

def check_custom_rules(fname, patterns):
    if not patterns:
        return []
    try:
        with open(fname, "rb") as f:
            data = f.read()
    except OSError:
        return []
    return [f"Custom rule: {p.pattern.decode(errors='replace')}" for p in patterns if p.search(data)]

def clamav_scan(filelist_path):
    """Runs the same file list through clamd (cxs's 'virusscan' equivalent).
    Returns a list of (path, signature) tuples. Silently returns [] if
    ClamAV isn't installed/running - it's an optional second detector,
    not a hard requirement."""
    if not shutil.which("clamdscan"):
        return []
    try:
        out = subprocess.run(
            ["clamdscan", "--fdpass", "--no-summary", "--infected",
             f"--file-list={filelist_path}"],
            capture_output=True, text=True, timeout=600,
        ).stdout
    except Exception:
        return []
    findings = []
    for line in out.splitlines():
        m = re.match(r"^(.+): (.+) FOUND$", line)
        if m:
            findings.append((m.group(1), m.group(2)))
    return findings

def iter_files(filelist_path, ignore_patterns=None, changed_hours=None, max_size=None):
    max_size = max_size or 5 * 1024 * 1024
    changed_cutoff = time.time() - float(changed_hours) * 3600 if changed_hours else None
    with open(filelist_path) as f:
        for line in f:
            fname = line.rstrip("\n")
            if not fname:
                continue
            if ignore_patterns and any(p in fname for p in ignore_patterns):
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

def main():
    if len(sys.argv) not in (4, 5) or sys.argv[1] not in ("whitelist", "scan"):
        print(f"Usage: {sys.argv[0]} whitelist|scan <php.yar> <filelist.txt> [clamav_filelist.txt]", file=sys.stderr)
        sys.exit(1)

    import yara
    mode, yar_path, filelist_path = sys.argv[1], sys.argv[2], sys.argv[3]
    # php.yar's rules require a <?php tag (IsPhp), so YARA only ever scans
    # the PHP file list. ClamAV has no such restriction - it can usefully
    # check a broader list (uploaded images/PDFs/etc. can carry malware
    # too), so it takes an optional separate, wider list.
    clamav_filelist_path = sys.argv[4] if len(sys.argv) == 5 else filelist_path

    # Our own rules (openxs-rules/*.yar, next to php.yar) cover real
    # malware families found missing from php-malware-finder's own
    # ruleset during OpenXS's corpus analysis - see
    # OpenXS-ops/TIMELINE.md, 2026-10-22.
    sources = {"php": yar_path}
    rules_dir = os.path.join(os.path.dirname(os.path.abspath(yar_path)), "openxs-rules")
    if os.path.isdir(rules_dir):
        for fn in sorted(os.listdir(rules_dir)):
            if fn.endswith(".yar"):
                sources[f"openxs_{fn[:-4]}"] = os.path.join(rules_dir, fn)
    rules = yara.compile(filepaths=sources, includes=True, error_on_warning=False)

    ignore_patterns = load_ignore_patterns(os.environ.get("OPENXS_IGNORE_FILE", "/etc/openxs/ignore"))
    changed_hours = os.environ.get("OPENXS_CHANGED_HOURS")
    quiet = os.environ.get("OPENXS_QUIET") == "1"
    throttle(os.environ.get("OPENXS_THROTTLE_LOAD"))
    custom_rules = load_custom_rules(os.environ.get("OPENXS_RULE_FILE", "/etc/openxs/rules"))

    if mode == "whitelist":
        entries = []
        for fname in iter_files(filelist_path, ignore_patterns, changed_hours):
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
        for fname in iter_files(filelist_path, ignore_patterns, changed_hours):
            total += 1
            matches = rules.match(fname, fast=True)
            real = [m for m in matches if m.rule != "IsWhitelisted" and m.rule != "IsPhp"]
            custom_hits = check_custom_rules(fname, custom_rules)
            if real or custom_hits:
                for rule_name in [m.rule for m in real] + custom_hits:
                    print(f"{fname}\t{rule_name}")
                    findings.append((fname, rule_name))
                hits += 1
        clam_findings = clamav_scan(clamav_filelist_path)
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
                           if not (ignore_patterns and any(pat in p for pat in ignore_patterns))]
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
                if clamav_filelist_path != filelist_path:
                    clam_note += " (ClamAV also covered a wider file list)"
                print(f"# Scanned {total} file(s), {hits} flagged (YARA after whitelist suppression + ClamAV + filesystem checks){clam_note}", file=sys.stderr)

        try:
            import openxs_db
            label = os.environ.get("OPENXS_SCAN_LABEL", filelist_path)
            scan_id = openxs_db.record_scan(label, total, findings)

            if os.environ.get("OPENXS_QUARANTINE_ENABLED") == "1" and findings:
                # cxs's own default: only quarantine Viruses and Known
                # Exploits, "to avoid otherwise breaking web sites" -
                # filesystem indicators (SUID/symlinks/binaries) are much
                # more likely to be legitimate, so they're opt-in.
                allowed = set(os.environ.get("OPENXS_QUARANTINE_CATEGORIES", "virus,yara").split(","))
                quarantined = 0
                for fid, _, rule_name, _ in openxs_db.findings_for_scan(scan_id):
                    if categorize(rule_name) in allowed and openxs_db.quarantine_file(fid):
                        quarantined += 1
                if quarantined:
                    print(f"# Quarantined {quarantined} file(s)", file=sys.stderr)
        except Exception as e:
            print(f"# (scan history not recorded: {e})", file=sys.stderr)

if __name__ == "__main__":
    main()
