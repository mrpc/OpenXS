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
import hashlib

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
        if total == 0:
            print("# Nothing to scan: no PHP files found under the given path(s).", file=sys.stderr)
        else:
            print(f"# Scanned {total} file(s), {hits} with a genuine hit (after whitelist suppression)", file=sys.stderr)

        try:
            import openxs_db
            label = os.environ.get("OPENXS_SCAN_LABEL", filelist_path)
            openxs_db.record_scan(label, total, findings)
        except Exception as e:
            print(f"# (scan history not recorded: {e})", file=sys.stderr)

if __name__ == "__main__":
    main()
