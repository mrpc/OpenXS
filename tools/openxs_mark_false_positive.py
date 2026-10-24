#!/usr/bin/env python3
"""CLI wrapper around openxs_db.record_false_positive() - a one-shot
audit-trail entry for a "Mark false positive" click anywhere in the
Webmin UI (mod_security blocks, YARA/ClamAV/maldet findings, version-
check "(oldversion)" findings), independent of whatever exclusion
mechanism (if any) was also applied for that source. Not itself a
detector or a suppression mechanism - just the record of the click,
for later review (e.g. a future telemetry/aggregation step)."""
import sys

import openxs_db


def main():
    if len(sys.argv) not in (4, 5):
        print(f"Usage: {sys.argv[0]} <source> <path> <detail> [action_taken]", file=sys.stderr)
        sys.exit(1)
    source, path, detail = sys.argv[1:4]
    action_taken = sys.argv[4] if len(sys.argv) == 5 else None
    openxs_db.record_false_positive(source, path, detail, action_taken=action_taken)
    print("Recorded.")


if __name__ == "__main__":
    main()
