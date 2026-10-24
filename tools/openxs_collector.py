#!/usr/bin/env python3
"""Single periodic entry point for OpenXS's own lightweight bookkeeping
jobs (stats caching, history recording) - one cron entry
(`*/5 * * * *`, see install.sh), one process, one place to add the next
such job, instead of a new /etc/cron.d file per feature.

Deliberately NOT for the actual exploit/virus scan itself
(run_scheduled_scan.sh) - that's a separate, much heavier, differently
-scheduled (daily) job with its own process lifecycle, dashboard
widget, and log. This is only for small, fast, "keep a cache/stat
fresh" work - a job here should reliably finish in well under the
5-minute interval.

Each job is a zero-argument callable returning a short status string.
One job's exception is reported and skipped, not allowed to stop the
others - a bug in one shouldn't silently also stop the rest from
running."""
import sys

import openxs_modsec_record

JOBS = [
    ("modsec", openxs_modsec_record.run),
]


def main():
    failed = False
    for name, job in JOBS:
        try:
            print(f"[{name}] {job()}")
        except Exception as e:
            failed = True
            print(f"[{name}] FAILED: {e}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
