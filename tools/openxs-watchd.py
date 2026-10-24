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
import signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pmf_scan

LOG = "/var/log/openxs-watchd.log"

# tracemalloc, gated by the same debug flag as _mem() below - chasing a
# leak whose exact source line kept eluding plain before/after RSS
# checkpoints (it explodes somewhere inside a single scan_one() call,
# fast enough that no checkpoint after it is ever reached). This dumps
# the top allocations by source line automatically the first time RSS
# crosses 300MB (well above normal ~15-50MB, well below the 1536MB
# kernel backstop - leaves time to actually log before the kill).
_TRACEMALLOC_ON = os.environ.get("OPENXS_WATCHD_MEM_DEBUG") == "1"
if _TRACEMALLOC_ON:
    import tracemalloc
    tracemalloc.start(10)
_tracemalloc_dumped = [False]


def _dump_tracemalloc():
    if not _TRACEMALLOC_ON or _tracemalloc_dumped[0]:
        return
    _tracemalloc_dumped[0] = True
    snapshot = tracemalloc.take_snapshot()
    log("TRACEMALLOC top 10 allocations by source line:")
    for stat in snapshot.statistics("lineno")[:10]:
        log(f"  {stat}")

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


def check_rss_guard(max_rss_kb):
    """Safety backstop, not a fix for any specific bug - whatever grows
    our own memory (a pathological custom rule, a future bug, anything),
    exit (non-zero, so systemd's Restart=on-failure brings us straight
    back) rather than silently growing until the kernel OOM-killer picks
    some unrelated process instead. Found for real on prod-host-3: a leak
    here once came within ~1GB of the server's entire free memory."""
    if max_rss_kb and pmf_scan.vmrss_kb() > max_rss_kb:
        log(f"RSS exceeded WATCHD_MAX_RSS_MB={max_rss_kb // 1024}MB - exiting so systemd restarts us")
        sys.exit(1)


def log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


# Per-phase memory logging, opt-in (OPENXS_WATCHD_MEM_DEBUG=1) - off by
# default to avoid permanently bloating the log, turned on specifically
# while chasing a real leak that recurred even after the earlier regex-
# backtracking fix. _mem() only ever logs on a GROWTH between phases
# (not every phase of every event), so a healthy run stays quiet and a
# leaking one shows exactly which phase, for which file, is responsible.
_MEM_DEBUG = os.environ.get("OPENXS_WATCHD_MEM_DEBUG") == "1"
_last_rss_kb = [0]


def _mem(label, fname=""):
    if not _MEM_DEBUG:
        return
    rss = pmf_scan.vmrss_kb()
    delta = rss - _last_rss_kb[0]
    _last_rss_kb[0] = rss
    if delta > 1024:  # only log >1MB jumps - otherwise every event logs noise
        log(f"MEM {label} {fname}: {rss // 1024}MB (+{delta // 1024}MB)")
    if rss > 300 * 1024:
        _dump_tracemalloc()


def scan_one(fname, ignore, custom_rules, path_overrides, global_fast_php_only):
    _mem("start", fname)
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

    _mem("pre-yara", fname)
    findings = []
    matches = pmf_scan.yara_match_via_daemon(fname)
    _mem("after-yara", fname)
    if matches is None:
        log(f"openxs-scand unreachable, skipping YARA check for {fname}")
    else:
        findings += [(fname, rule) for rule in matches if rule not in ("IsWhitelisted", "IsPhp")]
    findings += [(fname, r) for r in pmf_scan.check_custom_rules(fname, custom_rules)]
    _mem("after-custom-rules", fname)
    for f, sig in pmf_scan.clamav_scan([fname]):
        findings.append((f, f"{sig} (ClamAV)"))
    _mem("after-clamav", fname)

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
                os.environ.get("OPENXS_QUARANTINE_CATEGORIES", "virus,yara_exploit,maldet")).split(","))
            for fid, _, rule_name, _ in openxs_db.findings_for_scan(scan_id):
                if pmf_scan.categorize(rule_name) in allowed:
                    openxs_db.quarantine_file(fid)
    except Exception as e:
        log(f"(not recorded: {e})")
    _mem("after-db-record", fname)


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
    max_rss_kb = int(float(cfg.get("WATCHD_MAX_RSS_MB", "1024") or "1024") * 1024)
    os.environ.setdefault("OPENXS_QUARANTINE_ENABLED", cfg.get("QUARANTINE_ENABLED", "0"))
    os.environ.setdefault("OPENXS_QUARANTINE_CATEGORIES", cfg.get("QUARANTINE_CATEGORIES", "virus,yara_exploit,maldet"))

    log(f"Starting, watching: {', '.join(watch_paths)}")
    cmd = ["inotifywait", "-m", "-r", "-e", "create,modify,moved_to", "--format", "%w%f"] + watch_paths
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        check_rss_guard(max_rss_kb)
        fname = line.rstrip("\n")
        if fname and not rate_limited(fname, rate_count, rate_window, rate_cooldown):
            scan_one(fname, ignore, custom_rules, path_overrides, global_fast_php_only)


if __name__ == "__main__":
    main()
