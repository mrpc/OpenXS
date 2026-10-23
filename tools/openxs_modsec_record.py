#!/usr/bin/env python3
"""Run daily by cron (before Apache's own log rotation, see install.sh)
to persist mod_security's per-day block counts into openxs.db -
otherwise that history silently disappears once the Apache error logs
it's read from get rotated away. Records every day currently visible
in the logs each run (not just today), so a day doesn't get missed if
this didn't run for a day or two, and a fresh install backfills
whatever's already in the as-yet-unrotated logs for free."""
import sys

import openxs_db
import openxs_modsec_log


def main():
    counts = openxs_modsec_log.daily_counts()
    for date, count in counts.items():
        openxs_db.record_modsec_count(date, count)
    print(f"Recorded mod_security block counts for {len(counts)} day(s).")


if __name__ == "__main__":
    sys.exit(main())
