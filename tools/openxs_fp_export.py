#!/usr/bin/env python3
"""Renders every recorded "mark false positive" click
(false_positive_reports) as a ready-to-paste Markdown table for a
GitHub issue - there's no real telemetry pipeline yet, so this is the
manual stand-in: an operator copies this and pastes it into a new
issue on the OpenXS repo to help improve detection rules upstream."""
import datetime
import sys

import openxs_db


def render_markdown(rows):
    if not rows:
        return "No false positives have been marked on this server yet."
    lines = [
        "| When | Source | Path | Rule/Detail | Action taken |",
        "|---|---|---|---|---|",
    ]
    for reported_at, source, path, detail, action_taken in rows:
        when = datetime.datetime.fromtimestamp(reported_at).strftime("%Y-%m-%d %H:%M")
        # Escape '|' so a path/detail containing one doesn't break the
        # table - Markdown tables have no other escape for it.
        cell = lambda s: (s or "").replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {when} | {cell(source)} | {cell(path)} | {cell(detail)} | {cell(action_taken) or '-'} |")
    return "\n".join(lines)


def main():
    print(render_markdown(openxs_db.false_positive_reports()))


if __name__ == "__main__":
    sys.exit(main())
