#!/usr/bin/env python3
"""cxs Watch daemon equivalent - initial version, meant to evolve.

Unlike the mod_security hook (which only ever sees files at the moment
of an HTTP upload), this watches whole directories for ANY file
create/modify/move - files dropped via SSH, cron, FTP, or anything else
that isn't an HTTP upload. Uses inotifywait (inotify-tools) in recursive
monitor mode rather than reimplementing inotify bindings ourselves.

v1 scope, deliberately kept small:
  - one flat list of watched paths (WATCH_PATHS in openxs.conf), no
    per-account/per-user model yet (cxs's --allusers concept)
  - YARA + custom rules + ClamAV per changed file, reusing pmf_scan's
    own functions - no fs_scan (that's a directory-level sweep, a
    different shape of check than "a file just changed")
  - no rate-limiting/debounce yet (cxs's --Wsleep/--Wrateignore) - a
    file saved many times in a row will be rescanned every time

YARA matching goes through openxs-scand's socket (requires it to be
running) rather than compiling the ruleset again here - one compiled
copy in memory shared by the upload hook and this daemon, not two.
"""
import sys
import os
import subprocess
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pmf_scan

LOG = "/var/log/openxs-watchd.log"


def log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def scan_one(fname, ignore, custom_rules, path_overrides, global_fast_php_only):
    plain, md5s, sha256s = ignore
    if pmf_scan.is_ignored(fname, plain, md5s, sha256s):
        return
    if not os.path.isfile(fname):
        return  # deleted/moved again already
    fast = pmf_scan.effective_setting(fname, path_overrides, "fast_php_only", global_fast_php_only)
    if fast == "1" and not fname.endswith(".php"):
        return
    try:
        size = os.path.getsize(fname)
    except OSError:
        return
    if not (0 < size < 5 * 1024 * 1024):
        return

    findings = []
    matches = pmf_scan.yara_match_via_daemon(fname)
    if matches is None:
        log(f"openxs-scand unreachable, skipping YARA check for {fname}")
    else:
        findings += [(fname, rule) for rule in matches if rule not in ("IsWhitelisted", "IsPhp")]
    findings += [(fname, r) for r in pmf_scan.check_custom_rules(fname, custom_rules)]
    for f, sig in pmf_scan.clamav_scan([fname]):
        findings.append((f, f"{sig} (ClamAV)"))

    if not findings:
        return
    log(f"HIT {fname}: {', '.join(r for _, r in findings)}")
    try:
        import openxs_db
        scan_id = openxs_db.record_scan(f"watch:{fname}", 1, findings)
        q_enabled = os.environ.get("OPENXS_QUARANTINE_ENABLED", "0")
        q_enabled = pmf_scan.effective_setting(fname, path_overrides, "quarantine_enabled", q_enabled)
        if q_enabled == "1":
            allowed = set(pmf_scan.effective_setting(
                fname, path_overrides, "quarantine_categories",
                os.environ.get("OPENXS_QUARANTINE_CATEGORIES", "virus,yara")).split(","))
            for fid, _, rule_name, _ in openxs_db.findings_for_scan(scan_id):
                if pmf_scan.categorize(rule_name) in allowed:
                    openxs_db.quarantine_file(fid)
    except Exception as e:
        log(f"(not recorded: {e})")


def main():
    cfg_path = os.environ.get("OPENXS_CONFIG", "/etc/openxs/openxs.conf")
    cfg = {}
    if os.path.isfile(cfg_path):
        with open(cfg_path) as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    cfg[k] = v

    watch_paths = [p for p in cfg.get("WATCH_PATHS", "").split(",") if p.strip()]
    if not watch_paths:
        log("WATCH_PATHS is empty - nothing to watch, exiting")
        sys.exit(0)

    ignore = pmf_scan.load_ignore_patterns(os.environ.get("OPENXS_IGNORE_FILE", "/etc/openxs/ignore"))
    custom_rules = pmf_scan.load_custom_rules(os.environ.get("OPENXS_RULE_FILE", "/etc/openxs/rules"))
    path_overrides = pmf_scan.load_path_overrides(os.environ.get("OPENXS_PATH_SETTINGS", "/etc/openxs/path_settings"))
    global_fast_php_only = cfg.get("FAST_PHP_ONLY", "0")
    os.environ.setdefault("OPENXS_QUARANTINE_ENABLED", cfg.get("QUARANTINE_ENABLED", "0"))
    os.environ.setdefault("OPENXS_QUARANTINE_CATEGORIES", cfg.get("QUARANTINE_CATEGORIES", "virus,yara"))

    log(f"Starting, watching: {', '.join(watch_paths)}")
    cmd = ["inotifywait", "-m", "-r", "-e", "create,modify,moved_to", "--format", "%w%f"] + watch_paths
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        fname = line.rstrip("\n")
        if fname:
            scan_one(fname, ignore, custom_rules, path_overrides, global_fast_php_only)


if __name__ == "__main__":
    main()
