#!/usr/bin/env python3
"""Single source of truth for "what's working, what isn't" - used by the
Webmin dashboard, the CLI (--json or human-readable), and the MCP server,
so there's exactly one place that knows how to answer that question
instead of three different ad-hoc checks drifting apart.

Read-only: no action here changes anything on the server.
"""
import json
import os
import re
import subprocess
import sys

PMF_DIR = "/opt/php-malware-finder"
QUARANTINE_DIR = os.environ.get("OPENXS_QUARANTINE", "/var/lib/openxs/quarantine")
SCAN_SUMMARY_RE = re.compile(r"^# Scanned .*$", re.MULTILINE)


def _systemctl_is_active(unit):
    try:
        out = subprocess.run(["systemctl", "is-active", unit],
                              capture_output=True, text=True, timeout=5).stdout.strip()
        return out
    except Exception:
        return "unknown"


def daemon_status():
    return {
        "openxs-scand": _systemctl_is_active("openxs-scand"),
        "openxs-watchd": _systemctl_is_active("openxs-watchd"),
    }


def detector_status():
    return {
        "clamav": {
            "installed": os.access("/usr/bin/clamdscan", os.X_OK),
            "running": _systemctl_is_active("clamav-daemon"),
        },
        "maldet": {
            "installed": os.access("/usr/local/sbin/maldet", os.X_OK),
        },
    }


def last_scan_info():
    """Reads the scheduled/manual scan's own output files - no new state,
    just what run_scheduled_scan.sh / scan.cgi already write every run."""
    scan_log = os.path.join(PMF_DIR, "scan.log")
    if not os.path.exists(scan_log):
        return {"ran": False}
    try:
        with open(scan_log, errors="replace") as f:
            text = f.read()
    except OSError:
        return {"ran": False}
    matches = SCAN_SUMMARY_RE.findall(text)
    return {
        "ran": True,
        "at": os.path.getmtime(scan_log),
        "summary": matches[-1][2:] if matches else None,  # strip "# "
    }


def quarantine_count():
    try:
        return len([f for f in os.listdir(QUARANTINE_DIR) if os.path.isfile(os.path.join(QUARANTINE_DIR, f))])
    except OSError:
        return 0


def fim_info():
    """File integrity status - whether a baseline exists at all (fim.db),
    and the last scheduled check's own result file, same pattern as
    last_scan_info() above."""
    db_path = os.environ.get("OPENXS_FIM_DB", "/var/lib/openxs/fim.db")
    results_path = os.path.join(PMF_DIR, "fim_results.txt")
    if not os.path.exists(db_path):
        return {"baselined": False}
    info = {"baselined": True}
    if os.path.exists(results_path):
        try:
            with open(results_path, errors="replace") as f:
                text = f.read()
            info["checked_at"] = os.path.getmtime(results_path)
            info["summary"] = text.splitlines()[0].lstrip("# ") if text.strip() else None
        except OSError:
            pass
    return info


def version_scan_info():
    """Same pattern as last_scan_info()/fim_info() - reads
    version_results.txt, the WordPress core version check's own output
    from the last scheduled scan, rather than re-running it (that check
    makes a live network call, too slow for a status lookup)."""
    path = os.path.join(PMF_DIR, "version_results.txt")
    if not os.path.exists(path):
        return {"ran": False}
    try:
        with open(path, errors="replace") as f:
            text = f.read()
    except OSError:
        return {"ran": False}
    return {
        "ran": True,
        "at": os.path.getmtime(path),
        "summary": text.splitlines()[0].lstrip("# ") if text.strip() else None,
    }


def apt_security_info():
    """Same pattern as the other *_info() functions - reads the last
    scheduled scan's own apt_security_results.txt rather than re-running
    `apt-get update` (a live network/package-manager call, too slow and
    too side-effecting for a plain status lookup)."""
    path = os.path.join(PMF_DIR, "apt_security_results.txt")
    if not os.path.exists(path):
        return {"ran": False}
    try:
        with open(path, errors="replace") as f:
            text = f.read()
    except OSError:
        return {"ran": False}
    return {
        "ran": True,
        "at": os.path.getmtime(path),
        "summary": text.splitlines()[0].lstrip("# ") if text.strip() else None,
    }


def mailbox_scan_info():
    """Same pattern as the other *_info() functions - reads the last
    scheduled scan's own mailbox_results.txt. Returns ran=False both when
    it has never run AND when SCAN_MAILBOXES is off (no file either way -
    callers don't need to tell the two apart, "nothing to show" covers
    both)."""
    path = os.path.join(PMF_DIR, "mailbox_results.txt")
    if not os.path.exists(path):
        return {"ran": False}
    try:
        with open(path, errors="replace") as f:
            text = f.read()
    except OSError:
        return {"ran": False}
    lines = [l for l in text.splitlines() if l.strip()]
    summary = next((l.lstrip("# ") for l in lines if l.startswith("# Mailbox scan:")), None)
    return {
        "ran": True,
        "at": os.path.getmtime(path),
        "summary": summary,
    }


def full_status():
    return {
        "daemons": daemon_status(),
        "detectors": detector_status(),
        "last_scan": last_scan_info(),
        "quarantine_count": quarantine_count(),
        "fim": fim_info(),
        "version_scan": version_scan_info(),
        "apt_security": apt_security_info(),
        "mailbox_scan": mailbox_scan_info(),
    }


def main():
    status = full_status()
    if "--json" in sys.argv:
        print(json.dumps(status, indent=2))
        return
    d = status["daemons"]
    print(f"openxs-scand: {d['openxs-scand']}")
    print(f"openxs-watchd: {d['openxs-watchd']}")
    c = status["detectors"]["clamav"]
    print(f"ClamAV: installed={c['installed']} running={c['running']}")
    m = status["detectors"]["maldet"]
    print(f"maldet: installed={m['installed']}")
    ls = status["last_scan"]
    print(f"Last scan: {ls.get('summary', 'never ran')}")
    print(f"Quarantined files: {status['quarantine_count']}")
    fi = status["fim"]
    print(f"File integrity: {fi.get('summary', 'no baseline yet') if fi['baselined'] else 'no baseline yet'}")
    vs = status["version_scan"]
    print(f"WordPress version check: {vs.get('summary', 'never ran') if vs['ran'] else 'never ran'}")
    aps = status["apt_security"]
    print(f"Apt security updates: {aps.get('summary', 'never ran') if aps['ran'] else 'never ran'}")
    mb = status["mailbox_scan"]
    print(f"Mailbox virus scan: {mb.get('summary', 'never ran / disabled') if mb['ran'] else 'never ran / disabled'}")


if __name__ == "__main__":
    main()
