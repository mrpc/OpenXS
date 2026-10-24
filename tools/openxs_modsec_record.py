#!/usr/bin/env python3
"""One job for openxs_collector.py's periodic run - see that module for
the actual cron entry. Does two things, sharing a single grep pass
(_matching_lines()) across both instead of scanning every Apache error
log on the box twice:
  - persists mod_security's per-day block counts into openxs.db -
    otherwise that history silently disappears once the Apache error
    logs it's read from get rotated away. Records every day currently
    visible in the logs each run (not just today), so a day doesn't get
    missed if this didn't run for a while, and a fresh install
    backfills whatever's already in the as-yet-unrotated logs for free.
  - refreshes the "grouped by host/path/rule" view's cache
    (openxs_modsec_log.write_cache()), so viewing that page is a fast
    file read instead of a live grep across every Apache error log on
    the box on every single page view.

Still runnable standalone (python3 openxs_modsec_record.py) for manual
use/testing - the collector just imports run()."""
import sys

import openxs_db
import openxs_modsec_log


def run():
    """Returns a short human-readable status string."""
    lines = list(openxs_modsec_log._matching_lines())
    counts = openxs_modsec_log.daily_counts(lines=lines)
    for date, count in counts.items():
        openxs_db.record_modsec_count(date, count)
    openxs_modsec_log.write_cache(lines=lines)
    return f"recorded block counts for {len(counts)} day(s), refreshed the blocks-view cache"


if __name__ == "__main__":
    print(run())
    sys.exit(0)
