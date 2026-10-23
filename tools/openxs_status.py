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


def full_status():
    return {
        "daemons": daemon_status(),
        "detectors": detector_status(),
        "last_scan": last_scan_info(),
        "quarantine_count": quarantine_count(),
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


if __name__ == "__main__":
    main()
