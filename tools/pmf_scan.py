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

def iter_files(filelist_path):
    with open(filelist_path) as f:
        for line in f:
            fname = line.rstrip("\n")
            if not fname:
                continue
            try:
                size = os.path.getsize(fname)
            except OSError:
                continue
            if 0 < size < 5 * 1024 * 1024:
                yield fname

def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("whitelist", "scan"):
        print(f"Usage: {sys.argv[0]} whitelist|scan <php.yar> <filelist.txt>", file=sys.stderr)
        sys.exit(1)

    import yara
    mode, yar_path, filelist_path = sys.argv[1], sys.argv[2], sys.argv[3]
    rules = yara.compile(yar_path, includes=True, error_on_warning=False)

    if mode == "whitelist":
        entries = []
        for fname in iter_files(filelist_path):
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
        for fname in iter_files(filelist_path):
            total += 1
            matches = rules.match(fname, fast=True)
            real = [m for m in matches if m.rule != "IsWhitelisted" and m.rule != "IsPhp"]
            if real:
                for m in real:
                    print(f"{fname}\t{m.rule}")
                    findings.append((fname, m.rule))
                hits += 1
        clam_findings = clamav_scan(filelist_path)
        already_flagged = {f for f, _ in findings}
        for fname, sig in clam_findings:
            print(f"{fname}\t{sig} (ClamAV)")
            findings.append((fname, f"{sig} (ClamAV)"))
            if fname not in already_flagged:
                hits += 1
                already_flagged.add(fname)

        if total == 0:
            print("# Nothing to scan: no PHP files found under the given path(s).", file=sys.stderr)
        else:
            clam_note = f", {len(clam_findings)} ClamAV hit(s)" if shutil.which("clamdscan") else ""
            print(f"# Scanned {total} file(s), {hits} with a genuine hit (after whitelist suppression){clam_note}", file=sys.stderr)

        try:
            import openxs_db
            label = os.environ.get("OPENXS_SCAN_LABEL", filelist_path)
            scan_id = openxs_db.record_scan(label, total, findings)

            if os.environ.get("OPENXS_QUARANTINE_ENABLED") == "1" and findings:
                quarantined = 0
                for fid, _, _, _ in openxs_db.findings_for_scan(scan_id):
                    if openxs_db.quarantine_file(fid):
                        quarantined += 1
                if quarantined:
                    print(f"# Quarantined {quarantined} file(s)", file=sys.stderr)
        except Exception as e:
            print(f"# (scan history not recorded: {e})", file=sys.stderr)

if __name__ == "__main__":
    main()
