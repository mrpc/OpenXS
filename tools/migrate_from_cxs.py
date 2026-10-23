#!/usr/bin/env python3
"""
Migrates an existing cxs (ConfigServer eXploit Scanner) installation to
OpenXS: translates its settings, its ignore/xtra custom-rule files,
pulls its quarantine into OpenXS's own quarantine model so it stays
restorable/deletable through the normal UI, and imports its historical
scan logs (cxs.db) for continuity of scan history.

Real cxs behavior verified directly against a live installation (balrog)
rather than assumed from its documentation alone - including the fact
that its own crondaily.conf there is unused dead config: the actual
active cron job uses explicit CLI flags instead, which is why this
reads a cron line rather than only a config file.

Five independent, separately-runnable subcommands (dry-run by default -
pass --apply to actually write anything). Everything reads cxs without
touching it, except disable-exploitscan, which (only with --apply, and
only after showing exactly what it would change) edits cxs's own cron
entry to add --noexploitscan - the one piece of cxs this migration is
meant to make redundant.
"""
import argparse
import base64
import glob
import os
import re
import shlex
import sqlite3
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import openxs_db

# ---------------------------------------------------------------------------
# Settings (cron invocation -> openxs.conf)
# ---------------------------------------------------------------------------

# cxs --qoptions/--options letter -> OpenXS quarantine category (per cxs's
# own --help text). Letters with no OpenXS equivalent are reported as
# unsupported, never guessed at.
QOPTION_CATEGORY = {
    "m": "yara", "M": "yara", "h": "yara",
    "v": "virus",
    "f": "fs", "u": "fs", "S": "fs", "G": "fs", "c": "fs", "e": "fs", "x": "fs",
}
QOPTION_UNSUPPORTED = {
    "T": "quarantine all script files - too broad, no OpenXS equivalent category",
    "E": "email script detection - not implemented in OpenXS",
    "U": "upload script detection - not implemented in OpenXS",
    "B": "Bayesian probability scoring - not implemented in OpenXS (known gap)",
}

# Flags that take a value we don't translate but must still skip over
# correctly when walking the token list.
_VALUE_FLAGS_IGNORED = ("--report", "--template", "--logfile", "--config", "--comment")


def _invokes_cxs_binary(line):
    """True only if some whitespace-separated token in the line IS the
    cxs binary (exactly "cxs", or a path ending in "/cxs") - a plain
    substring check ("cxs" in line) also matches unrelated files that
    merely have "cxs" in their name, like cxs's own
    /etc/cxs/cxsdbupdate.pl housekeeping script (found for real on
    balrog - substring matching would have wrongly tried to append
    --noexploitscan to a Perl script invocation that doesn't take it)."""
    return any(tok == "cxs" or tok.endswith("/cxs") for tok in line.split())


def _cron_d_files():
    """/etc/cron.d/* filenames cron (via run-parts) actually executes -
    verified directly with `run-parts --list /etc/cron.d` on balrog
    rather than assumed: it skips a file like cxs-cron.bak-20251022 (a
    backup made before an earlier edit, found for real there), so a
    naive glob() would have offered to "fix" a cron job that never
    runs. Falls back to a plain glob if run-parts itself isn't
    available (e.g. this script running somewhere without it)."""
    try:
        out = subprocess.run(["run-parts", "--list", "/etc/cron.d"],
                              capture_output=True, text=True, timeout=5).stdout
        paths = out.splitlines()
        if paths:
            return paths
    except Exception:
        pass
    return glob.glob("/etc/cron.d/*")


def find_cxs_cron_sources():
    """Scans crontab -l and /etc/cron.d/* for non-commented lines invoking
    cxs - returns every candidate found as (source_type, path, line)
    triples, since a server can easily have more than one (daily +
    weekly, say) and there's no reliable way to know which is "the real"
    one without asking. source_type is "crontab" (path is None) or
    "file" (path is the /etc/cron.d/* file it came from) - needed so a
    caller that wants to edit a line back knows exactly where it lives,
    not just what it says."""
    sources = []
    try:
        out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if line.strip() and not line.strip().startswith("#") and _invokes_cxs_binary(line):
                sources.append(("crontab", None, line.strip()))
    except Exception:
        pass
    for path in _cron_d_files():
        try:
            with open(path, errors="replace") as f:
                for line in f:
                    if line.strip() and not line.strip().startswith("#") and _invokes_cxs_binary(line):
                        sources.append(("file", path, line.rstrip("\n")))
        except OSError:
            pass
    return sources


def find_cxs_cron_lines():
    """Just the raw lines, for callers (like cmd_settings) that only
    want to read them, not know/edit their source."""
    return [line for _, _, line in find_cxs_cron_sources()]


def parse_cron_line(line):
    """Extracts the `cxs ...` invocation's flags from a full cron line
    (schedule fields + user + command, e.g. "7 0 * * * root /usr/sbin/cxs
    --foo bar"). Returns a dict; unrecognized flags are collected under
    "_unrecognized" for visibility rather than silently dropped."""
    idx = line.find("cxs")
    if idx == -1:
        return {}
    tokens = shlex.split(line[idx:])
    settings = {"_unrecognized": []}
    i = 1  # tokens[0] is "cxs" or "/usr/sbin/cxs" itself
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--mail":
            settings["mail"] = tokens[i + 1]; i += 2
        elif tok == "--quarantine":
            settings["quarantine"] = tokens[i + 1]; i += 2
        elif tok == "--qoptions":
            settings["qoptions"] = tokens[i + 1]; i += 2
        elif tok == "--options":
            settings["options"] = tokens[i + 1]; i += 2
        elif tok == "--ignore":
            settings["ignore"] = tokens[i + 1]; i += 2
        elif tok == "--xtra":
            settings["xtra"] = tokens[i + 1]; i += 2
        elif tok == "--ctime":
            settings["ctime"] = tokens[i + 1]; i += 2
        elif tok == "--www":
            settings["www"] = True; i += 1
        elif tok in ("--all", "--allusers"):
            settings["allusers"] = True; i += 1
        elif tok == "--user":
            settings["user"] = tokens[i + 1]; i += 2
        elif tok == "--virusscan":
            settings["virusscan"] = True; i += 1
        elif tok == "--novirusscan":
            settings["virusscan"] = False; i += 1
        elif tok == "--exploitscan":
            settings["exploitscan"] = True; i += 1
        elif tok == "--noexploitscan":
            settings["exploitscan"] = False; i += 1
        elif tok == "--sversionscan":
            settings["sversionscan"] = True; i += 1
        elif tok == "--nosversionscan":
            settings["sversionscan"] = False; i += 1
        elif tok == "--probability":
            settings["probability"] = True; i += 1
        elif tok == "--noprobability":
            settings["probability"] = False; i += 1
        elif tok == "--qclean":
            settings["qclean"] = True; i += 2  # [days] - a maintenance-only action, never a scan
        elif tok in _VALUE_FLAGS_IGNORED:
            i += 2
        elif tok.startswith("--"):
            settings["_unrecognized"].append(tok)
            i += 1
        else:
            settings["has_resource"] = True  # a bare path/glob to scan, e.g. "cxs /home/user --options ..."
            i += 1
    return settings


def cron_line_runs_a_scan(line):
    """False for a maintenance-only invocation like `cxs --quarantine
    /home/quarantine --qclean 180` - found for real on balrog: it has no
    --noexploitscan either way, but it isn't performing any scan at all,
    so there's nothing to disable there. A scan needs either a resource
    to scan (--allusers/--all/--user, or a bare path) or --qclean to be
    absent entirely."""
    settings = parse_cron_line(line)
    if settings.get("qclean"):
        return False
    return bool(settings.get("allusers") or "user" in settings or settings.get("has_resource"))


def translate_settings(cxs_settings):
    """Returns (openxs_conf_dict, warnings). Only fills in keys we're
    confident translate cleanly; anything cxs supports that OpenXS
    genuinely doesn't (probability scoring, upload/email script
    detection, sversionscan's full app coverage) is reported as a
    warning, never silently dropped or guessed at."""
    conf = {}
    warnings = []

    if "mail" in cxs_settings:
        email = cxs_settings["mail"]
        conf["EMAIL"] = email if "@" in email else f"{email}@localhost"

    conf["SCAN_MODE"] = "accounts" if cxs_settings.get("allusers") else "path"
    conf["ACCOUNTS_SUBPATH"] = "public_html" if cxs_settings.get("www") else ""

    if "ctime" in cxs_settings:
        conf["CHANGED_HOURS"] = cxs_settings["ctime"]

    if "quarantine" in cxs_settings:
        conf["QUARANTINE_ENABLED"] = "1"
        warnings.append(f"cxs quarantined to {cxs_settings['quarantine']} - run this script's "
                         f"'quarantine' subcommand separately to import its existing contents")
        if "qoptions" not in cxs_settings:
            # cxs's own documented default when --quarantine is set but
            # --qoptions isn't given explicitly (verified in its --help)
            cxs_settings = {**cxs_settings, "qoptions": "Mv"}
            warnings.append("--quarantine was set without an explicit --qoptions - assumed cxs's own "
                             "documented default (Mv) rather than leaving this unset")

    if "qoptions" in cxs_settings:
        cats, unsupported = set(), []
        for letter in cxs_settings["qoptions"]:
            if letter in QOPTION_CATEGORY:
                cats.add(QOPTION_CATEGORY[letter])
            elif letter in QOPTION_UNSUPPORTED:
                unsupported.append(f"{letter} ({QOPTION_UNSUPPORTED[letter]})")
        conf["QUARANTINE_CATEGORIES"] = ",".join(sorted(cats)) or "virus,yara"
        if unsupported:
            warnings.append("--qoptions included letters with no OpenXS equivalent, skipped: " + "; ".join(unsupported))

    if cxs_settings.get("exploitscan") is False:
        warnings.append("cxs had --noexploitscan (presumably already replaced by OpenXS) - OpenXS's "
                         "own YARA scanning is always on, there's no equivalent toggle to migrate")
    if cxs_settings.get("virusscan"):
        warnings.append("cxs had --virusscan enabled, which (combined with --allusers and without "
                         "--www) scans an account's ENTIRE tree with ClamAV, not just mail - OpenXS's "
                         "own ClamAV pass already covers the web-content case (ACCOUNTS_SUBPATH) and "
                         "mailbox_scan.py (SCAN_MAILBOXES=1) covers mail specifically, but neither "
                         "replicates scanning e.g. backups/logs under the account home - review if "
                         "that mattered to you")
    if cxs_settings.get("sversionscan"):
        warnings.append("cxs had --sversionscan enabled (200+ apps/plugins) - OpenXS's own "
                         "version_scan.py only covers WordPress core + composer packages so far, "
                         "narrower by design (see TIMELINE.md), not a full replacement yet")
    if cxs_settings.get("probability"):
        warnings.append("cxs had --probability (Bayesian scoring) enabled - not implemented in "
                         "OpenXS, no migration path for this")
    if cxs_settings.get("_unrecognized"):
        warnings.append("Unrecognized cxs flags, not migrated: " + ", ".join(cxs_settings["_unrecognized"]))

    return conf, warnings


def cron_line_has_exploitscan_enabled(line):
    """cxs's own default is exploitscan ON unless --noexploitscan is
    explicitly passed - a line with neither flag still has it enabled.
    But only for a line that actually runs a scan at all - see
    cron_line_runs_a_scan() (e.g. a --qclean maintenance job never
    scans, so there's nothing here to disable)."""
    if not cron_line_runs_a_scan(line):
        return False
    return parse_cron_line(line).get("exploitscan") is not False


def disable_exploitscan_in_line(line):
    """Appends --noexploitscan - the simplest, safest edit (cxs's CLI
    parser doesn't care about flag order or a flag appearing twice;
    --noexploitscan here would just override an earlier implicit
    default), rather than trying to insert it at a specific position."""
    return line.rstrip() + " --noexploitscan"


def disable_cxs_exploitscan(apply=False):
    """Returns a list of (source_type, path, old_line, new_line) for
    every cxs cron entry that currently has exploitscan enabled -
    typically redundant once OpenXS is handling exploit detection
    instead. With apply=True, rewrites each source in place (the user
    crontab via `crontab -`, or the specific /etc/cron.d/* file),
    replacing only that exact line - never touches cxs's own binary,
    config, ignore/xtra files, or quarantine."""
    results = []
    for source_type, path, line in find_cxs_cron_sources():
        if not cron_line_has_exploitscan_enabled(line):
            continue
        new_line = disable_exploitscan_in_line(line)
        results.append((source_type, path, line, new_line))
        if not apply:
            continue
        if source_type == "crontab":
            current = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
            subprocess.run(["crontab", "-"], input=current.replace(line, new_line), text=True)
        else:
            with open(path) as f:
                content = f.read()
            with open(path, "w") as f:
                f.write(content.replace(line, new_line))
    return results


def write_conf_merged(conf, config_path="/etc/openxs/openxs.conf"):
    """Merges into an existing openxs.conf rather than overwriting it -
    preserves any keys this migration doesn't touch (WATCH_PATHS, etc.)."""
    existing = {}
    if os.path.exists(config_path):
        with open(config_path) as f:
            for line in f:
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.strip().partition("=")
                    existing[k] = v
    existing.update(conf)
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as f:
        for k, v in existing.items():
            f.write(f"{k}={v}\n")


# ---------------------------------------------------------------------------
# Ignore/xtra files -> OpenXS's ignore/rules files
# ---------------------------------------------------------------------------

def translate_ignore(lines):
    """cxs.ignore's real prefix list (verified against cxs's own
    reference.txt, not just its ignore file's own header comment, which
    turned out to be incomplete - hfile:/hdir:/hsym: and md5sum:/sha256:
    weren't mentioned there but are real, documented entry types):
      file:/dir:/sym:    - absolute path - maps directly (ours is
                           substring-based, already covers this)
      hfile:/hdir:/hsym: - same, but relative to each user's own homedir
                           when --allusers/--user is used - approximated
                           as the same substring (matches "/tmp" anywhere
                           a path contains it, not anchored to a homedir
                           boundary specifically - usually fine in
                           practice, flagged for a quick sanity check)
      user:              - ignore a whole account - approximated as
                           /home/<user>/ (our own ACCOUNTS_DIR convention)
      md5sum:/sha256:    - ignore an exact file by hash - maps directly
                           to OpenXS's own md5:/sha256: ignore entries
      puser:/pfile:/pdir:/psym:/match: - regex-based - OpenXS's own
                           ignore file gained 'regex:<pattern>' support
                           specifically so these carry over losslessly
                           (cxs uses Perl regex, ours is Python re -
                           flagged for a quick sanity check either way)
      script:/pscript:   - mod_security-specific, no equivalent concept
      fp:                - ignore one of cxs's own fingerprint catalog
                           IDs (e.g. [P1419]) - no equivalent catalog
      ip:                - ignore an IP for web/ftp uploads - no
                           equivalent concept in OpenXS's ignore file
    """
    entries, warnings = [], []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        prefix, _, value = line.partition(":")
        if prefix in ("file", "dir", "sym"):
            entries.append(value)
        elif prefix in ("hfile", "hdir", "hsym"):
            entries.append(value)
            warnings.append(f"{line} - migrated as a plain substring (was relative to each user's homedir in cxs) - sanity-check it doesn't now match somewhere unintended")
        elif prefix == "user":
            entries.append(f"/home/{value}/")
            warnings.append(f"user:{value} approximated as a /home/{value}/ path - verify your accounts actually live there")
        elif prefix == "md5sum":
            entries.append(f"md5:{value}")
        elif prefix == "sha256":
            entries.append(f"sha256:{value}")
        elif prefix in ("puser", "pfile", "pdir", "psym", "match"):
            entries.append(f"regex:{value}")
            warnings.append(f"{line} - migrated as a regex entry; cxs uses Perl regex, OpenXS's 'regex:' ignore uses Python re - verify this still means what you expect")
        elif prefix in ("script", "pscript"):
            warnings.append(f"{line} - mod_security-specific ignore, not migrated (no equivalent concept in OpenXS)")
        elif prefix == "fp":
            warnings.append(f"{line} - cxs's own fingerprint catalog ID, no equivalent catalog in OpenXS, not migrated")
        elif prefix == "ip":
            warnings.append(f"{line} - IP-based ignore for web/ftp uploads, no equivalent concept in OpenXS, not migrated")
        else:
            warnings.append(f"{line} - unrecognized entry type, not migrated")
    return entries, warnings


def translate_xtra(lines):
    """cxs.xtra: regall:/regphp:/regperl: are content regexes (OpenXS's
    rules file is also content-regex-based, same spirit - though cxs uses
    Perl regex and ours is Python re; most simple patterns are
    compatible, not guaranteed, flagged for review either way).
    md5sum:/sha256: map directly. regfile:/file: are PATH/NAME matches,
    not content - no equivalent (OpenXS's rules file only matches file
    content, never filename), reported rather than silently misapplied
    as a content regex."""
    entries, warnings = [], []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("Include ") or ":" not in line:
            continue
        prefix, _, value = line.partition(":")
        forced_quarantine = False
        if value.startswith("quarantine:"):
            value = value[len("quarantine:"):]
            forced_quarantine = True
        if prefix in ("regall", "regphp", "regperl"):
            entries.append(value)
            note = f"{line} - migrated as-is; cxs uses Perl regex, OpenXS's rules file uses Python re - verify this still means what you expect"
            if forced_quarantine:
                note += " (its 'quarantine:' force-quarantine modifier has no equivalent, migrated as a plain rule only)"
            warnings.append(note)
        elif prefix in ("md5sum", "sha256"):
            entries.append(f"{'md5' if prefix == 'md5sum' else 'sha256'}:{value}")
        elif prefix in ("regfile", "file"):
            warnings.append(f"{line} - matches a file NAME/path, not content; OpenXS's rules file is content-only, not migrated")
        else:
            warnings.append(f"{line} - unrecognized entry type, not migrated")
    return entries, warnings


def append_lines(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        for line in lines:
            f.write(line + "\n")


# ---------------------------------------------------------------------------
# Quarantine import
# ---------------------------------------------------------------------------

def find_cxs_quarantine_entries(quarantine_dir):
    """Walks a cxs quarantine directory for every .restore4 sidecar
    (plain key=value lines - verified directly against a real cxs
    quarantine, not assumed), parsing it for the original path and
    finding message. Returns a list of dicts."""
    entries = []
    for dirpath, _, filenames in os.walk(quarantine_dir):
        for name in filenames:
            if not name.endswith(".restore4"):
                continue
            restore_path = os.path.join(dirpath, name)
            fields = {}
            try:
                with open(restore_path, errors="replace") as f:
                    for line in f:
                        if "=" in line:
                            k, _, v = line.rstrip("\n").partition("=")
                            fields[k] = v
            except OSError:
                continue
            if "qfile" not in fields or "actfile" not in fields:
                continue
            message = fields.get("message", "")
            try:
                message = base64.b64decode(message + "=" * (-len(message) % 4)).decode(errors="replace")
            except Exception:
                pass
            entries.append({
                "restore_path": restore_path,
                "qfile": fields["qfile"],
                "actfile": fields["actfile"],
                "message": message or "Known exploit (migrated from cxs)",
                "time": fields.get("time"),
            })
    return entries


def import_quarantine(quarantine_dir, apply=False):
    """Returns (imported_count, skipped_paths) - skipped: the qfile a
    .restore4 sidecar points to no longer exists (already restored or
    deleted outside cxs), noted rather than treated as an error."""
    entries = find_cxs_quarantine_entries(quarantine_dir)
    imported, skipped = 0, []
    for e in entries:
        if not os.path.exists(e["qfile"]):
            skipped.append(e["qfile"])
            continue
        if apply:
            quarantined_at = float(e["time"]) if e["time"] and e["time"].isdigit() else None
            openxs_db.import_quarantined_finding(e["actfile"], e["qfile"], e["message"], quarantined_at)
        imported += 1
    return imported, skipped


# ---------------------------------------------------------------------------
# Historical logs (cxs.db) -> OpenXS's scan-history db + archived report files
# ---------------------------------------------------------------------------

def _read_cxs_db(cxs_db_path, query):
    conn = sqlite3.connect(f"file:{cxs_db_path}?mode=ro", uri=True)
    try:
        return conn.execute(query).fetchall()
    finally:
        conn.close()


def find_cxs_db_findings(cxs_db_path):
    """cxs.db's own `files` table - its per-finding history log, verified
    directly against balrog's real data: plain-text `message` field (not
    base64, unlike the quarantine .restore4 sidecar's own message field -
    a different encoding for the same kind of text, in the same cxs
    install, so don't assume one matches the other on some other
    server). Includes hits that were only logged, never quarantined -
    broader than what find_cxs_quarantine_entries() alone would ever see
    (that one can only know about a hit that left a .restore4 sidecar
    behind)."""
    rows = _read_cxs_db(cxs_db_path, "SELECT timestamp, actfile, message FROM files")
    return [{"timestamp": t, "actfile": a, "message": m} for t, a, m in rows]


def find_cxs_db_reports(cxs_db_path):
    """cxs.db's own `reports` table - one full scan-run's text report per
    row (its own --dbreport feature), tens of MB each on a long-lived
    install. Too large and unstructured to import as per-finding data
    (it's a human-readable log, not records) - archived as plain files
    instead, see import_logs()."""
    rows = _read_cxs_db(cxs_db_path, "SELECT id, timestamp, title, dbreport FROM reports")
    return [{"id": i, "timestamp": t, "title": ti, "dbreport": d} for i, t, ti, d in rows]


def import_logs(cxs_db_path, reports_out_dir, apply=False):
    """Returns (finding_count, report_count). Findings go into OpenXS's
    own scan-history db as one batch "migrated from cxs" scan - read-
    only history, quarantine_path always left unset here (that's the
    separate 'quarantine' subcommand's job; a finding can show up via
    both without conflict, just without quarantine info on this path).
    Report text blobs are dumped to plain files, not imported as
    structured data - see find_cxs_db_reports()."""
    if not os.path.exists(cxs_db_path):
        return 0, 0
    findings = find_cxs_db_findings(cxs_db_path)
    reports = find_cxs_db_reports(cxs_db_path)

    if apply and findings:
        openxs_db.record_scan("migrated from cxs (historical logs)", len(findings),
                               [(f["actfile"] or "(unknown)", f["message"] or "(no message)") for f in findings])
    if apply and reports:
        os.makedirs(reports_out_dir, exist_ok=True)
        for r in reports:
            fname = f"{r['timestamp']}_{r['id']}.log"
            with open(os.path.join(reports_out_dir, fname), "w", errors="replace") as f:
                f.write(r["dbreport"] or "")

    return len(findings), len(reports)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_settings(args):
    lines = [args.cron_line] if args.cron_line else find_cxs_cron_lines()
    if not lines:
        print("No cxs cron invocation found (checked crontab -l and /etc/cron.d/*) - "
              "pass --cron-line 'the exact line' yourself.", file=sys.stderr)
        sys.exit(1)
    if len(lines) > 1 and not args.cron_line:
        print(f"# Found {len(lines)} candidate cxs cron line(s) - using the first. "
              f"Pass --cron-line explicitly if this is the wrong one:", file=sys.stderr)
        for l in lines:
            print(f"#   {l}", file=sys.stderr)
    cxs_settings = parse_cron_line(lines[0])
    conf, warnings = translate_settings(cxs_settings)
    print("# Translated openxs.conf settings:")
    for k, v in conf.items():
        print(f"{k}={v}")
    print(f"\n# {len(warnings)} item(s) need your attention (not auto-migrated, or approximated):")
    for w in warnings:
        print(f"#  - {w}")
    if args.apply:
        write_conf_merged(conf)
        print("\n# Written to /etc/openxs/openxs.conf (merged with existing settings).")
    else:
        print("\n# Dry run - pass --apply to actually write /etc/openxs/openxs.conf")


def cmd_rules(args):
    ignore_entries, ignore_warnings = [], []
    if os.path.exists(args.ignore_file):
        with open(args.ignore_file, errors="replace") as f:
            ignore_entries, ignore_warnings = translate_ignore(f.readlines())
    xtra_entries, xtra_warnings = [], []
    if os.path.exists(args.xtra_file):
        with open(args.xtra_file, errors="replace") as f:
            xtra_entries, xtra_warnings = translate_xtra(f.readlines())

    print(f"# {args.ignore_file}: {len(ignore_entries)} entrie(s) translatable -> /etc/openxs/ignore")
    for e in ignore_entries:
        print(f"IGNORE\t{e}")
    print(f"\n# {args.xtra_file}: {len(xtra_entries)} entrie(s) translatable -> /etc/openxs/rules")
    for e in xtra_entries:
        print(f"RULE\t{e}")
    all_warnings = ignore_warnings + xtra_warnings
    print(f"\n# {len(all_warnings)} item(s) need your attention (not auto-migrated, or approximated):")
    for w in all_warnings:
        print(f"#  - {w}")
    if args.apply:
        append_lines("/etc/openxs/ignore", ignore_entries)
        append_lines("/etc/openxs/rules", xtra_entries)
        print("\n# Appended to /etc/openxs/ignore and /etc/openxs/rules.")
    else:
        print("\n# Dry run - pass --apply to actually write these files")


def cmd_quarantine(args):
    entries = find_cxs_quarantine_entries(args.quarantine_dir)
    print(f"# Found {len(entries)} quarantined file(s) under {args.quarantine_dir}")
    imported, skipped = import_quarantine(args.quarantine_dir, apply=args.apply)
    print(f"# {imported} importable, {len(skipped)} skipped (already restored/deleted outside cxs)")
    for p in skipped:
        print(f"SKIPPED\t{p}")
    if args.apply:
        print(f"\n# Imported {imported} file(s) into OpenXS's own quarantine - view them under Quarantine in the dashboard.")
    else:
        print("\n# Dry run - pass --apply to actually move files and register them in OpenXS")


def cmd_logs(args):
    if not os.path.exists(args.cxsdb):
        print(f"# {args.cxsdb} not found - nothing to do.", file=sys.stderr)
        sys.exit(1)
    finding_count, report_count = import_logs(args.cxsdb, args.reports_out_dir, apply=args.apply)
    print(f"# {args.cxsdb}: {finding_count} historical finding(s) in its 'files' table, "
          f"{report_count} full scan report(s) in its 'reports' table")
    if args.apply:
        print(f"\n# Imported {finding_count} finding(s) into OpenXS's scan history (read-only - no "
              f"quarantine info here, use the 'quarantine' subcommand for that).")
        print(f"# Archived {report_count} report(s) as plain text files under {args.reports_out_dir}")
    else:
        print("\n# Dry run - pass --apply to actually import findings and archive reports")


def cmd_disable_exploitscan(args):
    results = disable_cxs_exploitscan(apply=args.apply)
    if not results:
        print("# No cxs cron entry found with exploitscan enabled - nothing to do.")
        return
    for source_type, path, old_line, new_line in results:
        where = path if source_type == "file" else "crontab -l"
        print(f"# {where}:")
        print(f"- {old_line}")
        print(f"+ {new_line}")
    if args.apply:
        print(f"\n# Disabled exploitscan in {len(results)} cxs cron entrie(s) - OpenXS's own YARA "
              f"scanning already covers this, nothing else about cxs was touched.")
    else:
        print(f"\n# Dry run - {len(results)} entrie(s) would change. Pass --apply to actually make this change")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("settings", help="Translate a cxs cron invocation into openxs.conf")
    p.add_argument("--cron-line", help="The exact cron line cxs runs from, if auto-discovery finds none or the wrong one")
    p.add_argument("--apply", action="store_true")
    p.set_defaults(func=cmd_settings)

    p = sub.add_parser("rules", help="Translate cxs.ignore/cxs.xtra into OpenXS's ignore/rules files")
    p.add_argument("--ignore-file", default="/etc/cxs/cxs.ignore")
    p.add_argument("--xtra-file", default="/etc/cxs/cxs.xtra")
    p.add_argument("--apply", action="store_true")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("quarantine", help="Import cxs's quarantine into OpenXS's own quarantine db")
    p.add_argument("--quarantine-dir", default="/home/quarantine")
    p.add_argument("--apply", action="store_true")
    p.set_defaults(func=cmd_quarantine)

    p = sub.add_parser("logs", help="Import cxs's historical scan logs (cxs.db) into OpenXS")
    p.add_argument("--cxsdb", default="/etc/cxs/cxs.db")
    p.add_argument("--reports-out-dir", default="/var/log/openxs-cxs-reports")
    p.add_argument("--apply", action="store_true")
    p.set_defaults(func=cmd_logs)

    p = sub.add_parser("disable-exploitscan", help="Disable cxs's own exploitscan in its cron entries (OpenXS already replaces it) - nothing else about cxs is touched")
    p.add_argument("--apply", action="store_true")
    p.set_defaults(func=cmd_disable_exploitscan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
