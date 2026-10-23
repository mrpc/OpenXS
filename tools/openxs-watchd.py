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

Rate limiting (cxs's --Wrateignore): if the same file is scanned more
than WATCH_RATE_COUNT times within WATCH_RATE_WINDOW seconds (a log file
or cache file being rewritten constantly, say), it's ignored for
WATCH_RATE_COOLDOWN seconds instead of being rescanned on every single
write.

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

# Per-file recent-event timestamps and cooldown-until times, both module-
# level so a single daemon process (one inotifywait loop, no threading)
# can just check/update them inline - no locking needed.
_recent = {}
_ignored_until = {}
_last_sweep_ts = 0.0


def _sweep_stale(now, window):
    """Without this, _recent gains one permanent entry per distinct
    filename ever seen, even a one-off temp/cache file touched a
    couple of times and never again - under heavy per-request file
    churn (a busy PHP process creating lots of uniquely-named files)
    that's an unbounded leak: found for real on prod-host-3, where it
    pushed the daemon's RSS past 8GB within 20 minutes. Runs at most
    once per `window` seconds (not on every single event), dropping
    any entry whose last event has already aged out of the window."""
    global _last_sweep_ts
    if now - _last_sweep_ts < window:
        return
    _last_sweep_ts = now
    for fname, times in list(_recent.items()):
        if not times or now - times[-1] >= window:
            del _recent[fname]
    for fname, until in list(_ignored_until.items()):
        if now >= until:
            del _ignored_until[fname]


def rate_limited(fname, count, window, cooldown):
    """True if fname has been scanned too often recently and should be
    skipped. Clears its own state once the cooldown expires."""
    now = time.time()
    _sweep_stale(now, window)
    until = _ignored_until.get(fname)
    if until is not None:
        if now < until:
            return True
        del _ignored_until[fname]
        _recent.pop(fname, None)

    times = [t for t in _recent.get(fname, []) if now - t < window]
    times.append(now)
    _recent[fname] = times
    if len(times) > count:
        _ignored_until[fname] = now + cooldown
        log(f"RATE-LIMITED {fname}: scanned {len(times)} times in {window}s, ignoring for {cooldown}s")
        return True
    return False


def log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def scan_one(fname, ignore, custom_rules, path_overrides, global_fast_php_only):
    plain, md5s, sha256s, regexes = ignore
    if pmf_scan.is_ignored(fname, plain, md5s, sha256s, regexes):
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
                os.environ.get("OPENXS_QUARANTINE_CATEGORIES", "virus,yara,maldet")).split(","))
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
        # No explicit paths given - fall back to the same account-wide
        # scope as scheduled/manual scans (cxs's --allusers --www), not
        # just sitting idle. Still opt-in in spirit: it only kicks in
        # once an admin actually starts this daemon.
        import glob
        accounts_dir = cfg.get("ACCOUNTS_DIR", "/home")
        subpath = cfg.get("ACCOUNTS_SUBPATH", "public_html")
        pattern = f"{accounts_dir}/*/{subpath}" if subpath else f"{accounts_dir}/*"
        watch_paths = [p for p in glob.glob(pattern) if os.path.isdir(p)]
        if not watch_paths:
            log(f"WATCH_PATHS is empty and no accounts found under {pattern} - nothing to watch, exiting")
            sys.exit(0)
        log(f"WATCH_PATHS is empty - defaulting to every account's web root ({pattern})")

    ignore = pmf_scan.load_ignore_patterns(os.environ.get("OPENXS_IGNORE_FILE", "/etc/openxs/ignore"))
    custom_rules = pmf_scan.load_custom_rules(os.environ.get("OPENXS_RULE_FILE", "/etc/openxs/rules"))
    path_overrides = pmf_scan.load_path_overrides(os.environ.get("OPENXS_PATH_SETTINGS", "/etc/openxs/path_settings"))
    global_fast_php_only = cfg.get("FAST_PHP_ONLY", "0")
    rate_count = int(cfg.get("WATCH_RATE_COUNT", "5") or "5")
    rate_window = float(cfg.get("WATCH_RATE_WINDOW", "10") or "10")
    rate_cooldown = float(cfg.get("WATCH_RATE_COOLDOWN", "60") or "60")
    os.environ.setdefault("OPENXS_QUARANTINE_ENABLED", cfg.get("QUARANTINE_ENABLED", "0"))
    os.environ.setdefault("OPENXS_QUARANTINE_CATEGORIES", cfg.get("QUARANTINE_CATEGORIES", "virus,yara,maldet"))

    log(f"Starting, watching: {', '.join(watch_paths)}")
    cmd = ["inotifywait", "-m", "-r", "-e", "create,modify,moved_to", "--format", "%w%f"] + watch_paths
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        fname = line.rstrip("\n")
        if fname and not rate_limited(fname, rate_count, rate_window, rate_cooldown):
            scan_one(fname, ignore, custom_rules, path_overrides, global_fast_php_only)


if __name__ == "__main__":
    main()
