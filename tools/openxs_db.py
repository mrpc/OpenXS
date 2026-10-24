#!/usr/bin/env python3
"""
Minimal scan-history + quarantine store for OpenXS (SQLite, stdlib only - no
new dependency). Mirrors the two things cxs's own cxs.db / quarantine dir
covered that we didn't have yet.
"""
import datetime
import os
import sqlite3
import time

DB_PATH = os.environ.get("OPENXS_DB", "/var/lib/openxs/openxs.db")
QUARANTINE_DIR = os.environ.get("OPENXS_QUARANTINE", "/var/lib/openxs/quarantine")

# Bump this whenever a migration (new ALTER TABLE, new CREATE TABLE) is
# added below - stored in the db file itself via PRAGMA user_version, so
# a fresh process can skip all migration DDL with one cheap read instead
# of re-running CREATE TABLE IF NOT EXISTS + several ALTER TABLE/except
# attempts on every single process start.
SCHEMA_VERSION = 7

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    path TEXT NOT NULL,
    files_scanned INTEGER NOT NULL,
    hits INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    file_path TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    quarantine_path TEXT
);
-- size: added after the initial release, via ALTER TABLE below (same
-- reason as scans.duration/load_avg - a table that already exists
-- doesn't pick up a new CREATE TABLE column).
CREATE TABLE IF NOT EXISTS daily_stats (
    date TEXT PRIMARY KEY,
    scan_count INTEGER NOT NULL DEFAULT 0,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    hits INTEGER NOT NULL DEFAULT 0,
    quarantined INTEGER NOT NULL DEFAULT 0,
    total_duration REAL NOT NULL DEFAULT 0,
    duration_count INTEGER NOT NULL DEFAULT 0
);
-- Added once real production data (6438 migrated findings) showed
-- search_findings()/quarantined_files() sorting by date - a JOIN across
-- these two tables - doing a full scan+sort every time: ~35ms cold,
-- against ~0.1ms for the old, index-backed "ORDER BY f.id" alone.
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_quarantine_path ON findings(quarantine_path);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);
-- mod_security block counts, recorded daily by cron (openxs_modsec_record.py)
-- rather than read live from Apache's error logs on every Stats page view -
-- those logs get rotated/compressed/deleted (logrotate), so anything older
-- than the rotation window would otherwise silently disappear from a
-- 30/90/365-day chart. Same one-row-per-day shape as daily_stats.
CREATE TABLE IF NOT EXISTS modsec_daily_stats (
    date TEXT PRIMARY KEY,
    blocks INTEGER NOT NULL DEFAULT 0
);
-- Every "Mark false positive" click, across every detector (mod_security,
-- YARA/ClamAV/maldet findings, version-check "(oldversion)" findings) -
-- a plain audit trail for later aggregation (e.g. future telemetry, or
-- just "what have we marked FP this month"), independent of whatever
-- exclusion mechanism (if any) was also applied at the same time.
CREATE TABLE IF NOT EXISTS false_positive_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reported_at REAL NOT NULL,
    source TEXT NOT NULL,
    path TEXT NOT NULL,
    detail TEXT NOT NULL,
    action_taken TEXT
);
CREATE INDEX IF NOT EXISTS idx_fp_reports_reported_at ON false_positive_reports(reported_at);
-- Every CSF auto-ban attempt the watch daemon makes (csf_autoban.py) -
-- an audit trail independent of CSF's own logs, so "what did OpenXS
-- itself decide to ban, and why" is visible from inside OpenXS too.
-- success=0 rows (csf -td itself failed) are kept too, not just
-- successful bans - worth knowing CSF rejected/couldn't apply one.
CREATE TABLE IF NOT EXISTS csf_auto_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    banned_at REAL NOT NULL,
    ip TEXT NOT NULL,
    file_path TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    ttl TEXT NOT NULL,
    success INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_csf_auto_bans_banned_at ON csf_auto_bans(banned_at);
"""


_schema_initialized_for = None  # DB_PATH this process already ran the schema/migration for
_connections = {}  # DB_PATH -> the one real sqlite3.Connection this process keeps open for it


class _KeepOpenConnection:
    """Wraps the real, cached connection so every existing conn.close()
    call site (there are over a dozen in this file) becomes a safe
    no-op, instead of having to rewrite each one - the real connection
    stays open and is reused across calls in this process rather than
    reconnecting every time (see _connect()'s own docstring for why
    that matters)."""
    def __init__(self, real_conn):
        self._real = real_conn

    def __getattr__(self, name):
        return getattr(self._real, name)

    def close(self):
        pass  # no-op - the real connection is cached and reused


def _connect():
    """Benchmarked three things before landing here, since a guess
    would've been wrong twice over: SQLite's default fsync-per-commit
    was ~13ms/call (not schema DDL re-execution, which a first fix
    wrongly assumed); switching to WAL+NORMAL (SQLite's own documented
    safe pairing - still durable against an application crash, only
    synchronous=OFF risks real corruption and is never used here) cut
    that to ~0.006ms/call *once a connection is reused*, but opening a
    brand new connection every call turned out to cost ~25ms on its
    own, becoming the new bottleneck. This matters because
    openxs-watchd.py calls record_scan() (and this) on every single
    file-change event it reacts to - real, compounding overhead on a
    busy shared-hosting server with frequent file writes, not just an
    occasional cron-triggered scan's problem."""
    global _schema_initialized_for
    if DB_PATH not in _connections:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        real_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        real_conn.execute("PRAGMA journal_mode=WAL")
        real_conn.execute("PRAGMA synchronous=NORMAL")
        _connections[DB_PATH] = real_conn
    conn = _connections[DB_PATH]
    # _schema_initialized_for skips this entirely for the rest of a
    # long-running process's lifetime (watchd) - zero DB round-trips.
    # But a cron-triggered scan or a Webmin python3 -c call is a brand
    # new, short-lived process every time, so re-running CREATE TABLE
    # IF NOT EXISTS + several ALTER TABLE-and-catch-the-exception
    # attempts was still happening once per process start, every start,
    # forever - cheap individually, but needless: PRAGMA user_version
    # stores a single integer IN the database file itself specifically
    # for this (asked about directly - this is the standard SQLite
    # pattern, not something to keep reinventing with try/except
    # probing). One cheap read tells us immediately whether any
    # migration work is needed at all.
    if _schema_initialized_for != DB_PATH:
        current_version = conn.execute("PRAGMA user_version").fetchone()[0]
        if current_version < SCHEMA_VERSION:
            conn.executescript(SCHEMA)
            # Added after the initial release - ALTER TABLE, not a
            # CREATE TABLE clause, since that only applies to a table
            # that doesn't exist yet and an existing openxs.db already
            # has the old `scans` schema. Still guarded by its own
            # try/except too (not just the version check above) in case
            # someone's DB_PATH was hand-edited or migrated oddly.
            for column in ("duration REAL", "load_avg REAL"):
                try:
                    conn.execute(f"ALTER TABLE scans ADD COLUMN {column}")
                except sqlite3.OperationalError:
                    pass  # already added in a previous run
            try:
                conn.execute("ALTER TABLE findings ADD COLUMN size INTEGER")
            except sqlite3.OperationalError:
                pass  # already added in a previous run
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        _schema_initialized_for = DB_PATH
    return _KeepOpenConnection(conn)


def record_false_positive(source, path, detail, action_taken=None):
    """source: 'modsec' / 'finding' / 'oldversion'. action_taken: a short
    description of what exclusion (if any) was also applied at the same
    time (e.g. "rule 930120 excluded (ARGS)", "added to ignore file"),
    or None if nothing could be auto-excluded for this source."""
    conn = _connect()
    conn.execute(
        "INSERT INTO false_positive_reports (reported_at, source, path, detail, action_taken) VALUES (?, ?, ?, ?, ?)",
        (time.time(), source, path, detail, action_taken),
    )
    conn.commit()


def false_positive_daily_stats_filled(days=30):
    """Same gap-filling shape as modsec_daily_stats_filled() - one
    (date, count) row per calendar day in the window. Computed directly
    from false_positive_reports (no separate daily-aggregate table
    needed - one row per click is a low enough volume to just count
    from the raw rows on every Stats page view)."""
    conn = _connect()
    rows = conn.execute(
        "SELECT date(reported_at, 'unixepoch') AS d, COUNT(*) FROM false_positive_reports "
        "WHERE reported_at >= strftime('%s', date('now', ?)) GROUP BY d",
        (f"-{int(days)} days",),
    ).fetchall()
    conn.close()
    by_date = {row[0]: row[1] for row in rows}
    today = datetime.date.today()
    result = []
    for offset in range(int(days) - 1, -1, -1):
        day = (today - datetime.timedelta(days=offset)).isoformat()
        result.append((day, by_date.get(day, 0)))
    return result


def false_positive_counts_by_source():
    """{source: count} across all time - for a short summary line on
    the Stats page, not broken down by day."""
    conn = _connect()
    rows = conn.execute("SELECT source, COUNT(*) FROM false_positive_reports GROUP BY source").fetchall()
    conn.close()
    return dict(rows)


def false_positive_reports(limit=500):
    """Every "mark false positive" click ever recorded, newest first -
    for the export page (false_positive_export.cgi), meant to be pasted
    into a GitHub issue to help improve detection rules upstream, since
    there's no real telemetry pipeline yet."""
    conn = _connect()
    rows = conn.execute(
        "SELECT reported_at, source, path, detail, action_taken FROM false_positive_reports "
        "ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def record_csf_ban(ip, file_path, rule_name, ttl, success):
    conn = _connect()
    conn.execute(
        "INSERT INTO csf_auto_bans (banned_at, ip, file_path, rule_name, ttl, success) VALUES (?, ?, ?, ?, ?, ?)",
        (time.time(), ip, file_path, rule_name, ttl, 1 if success else 0),
    )
    conn.commit()


def recent_csf_bans(limit=100):
    conn = _connect()
    rows = conn.execute(
        "SELECT banned_at, ip, file_path, rule_name, ttl, success FROM csf_auto_bans ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def record_scan(path, files_scanned, findings, duration=None, load_avg=None):
    """findings: list of (file_path, rule_name) tuples. Each finding's
    file size is captured now (the file still sits where it was found -
    quarantine, if any, is always a later, separate step) rather than
    left for a viewer to re-stat later, by which point the file may
    already be quarantined/gone."""
    conn = _connect()
    started_at = time.time()
    cur = conn.execute(
        "INSERT INTO scans (started_at, path, files_scanned, hits, duration, load_avg) VALUES (?, ?, ?, ?, ?, ?)",
        (started_at, path, files_scanned, len(findings), duration, load_avg),
    )
    scan_id = cur.lastrowid
    for f, r in findings:
        try:
            size = os.path.getsize(f)
        except OSError:
            size = None
        conn.execute(
            "INSERT INTO findings (scan_id, file_path, rule_name, size) VALUES (?, ?, ?, ?)",
            (scan_id, f, r, size),
        )
    day = time.strftime("%Y-%m-%d", time.gmtime(started_at))
    _bump_daily_stat(conn, day, scan_count=1, files_scanned=files_scanned, hits=len(findings),
                      total_duration=duration or 0, duration_count=1 if duration is not None else 0)
    conn.commit()
    conn.close()
    return scan_id


def new_finding_ids(scan_id):
    """(file_path, rule_name) pairs from this scan that were never seen
    in any earlier scan with the same path/rule/size - i.e. this is the
    first time this exact finding showed up, not an unmodified file
    that's been flagged on every single scan since it was installed.

    Used to make the scheduled-scan email alert only on genuinely new
    heuristic/fs findings (an unchanged legitimate-but-obfuscated-
    looking plugin file shouldn't nag forever) while still always
    alerting on serious ones (virus/yara_exploit/maldet) regardless -
    an unresolved real backdoor should keep nagging until it's actually
    quarantined, not go quiet just because it's been seen before.

    size is part of the comparison (cheap proxy for "did the file
    change" - exact hashing would be more precise but is wasted cost
    for files this is mainly meant to quiet down, which rarely change
    at all) - a file whose content changed (even at the same path,
    same rule) is treated as new again."""
    conn = _connect()
    rows = conn.execute(
        """
        SELECT f1.file_path, f1.rule_name FROM findings f1
        WHERE f1.scan_id = ?
          AND NOT EXISTS (
              SELECT 1 FROM findings f2
              WHERE f2.scan_id < f1.scan_id
                AND f2.file_path = f1.file_path
                AND f2.rule_name = f1.rule_name
                AND f2.size IS f1.size
          )
        """,
        (scan_id,),
    ).fetchall()
    conn.close()
    return rows


def quarantine_file(finding_id):
    """Moves a finding's file into the quarantine dir and records the new
    path. Returns the quarantine path, or None if the file no longer exists
    (already moved/deleted) or was already quarantined."""
    conn = _connect()
    row = conn.execute(
        "SELECT file_path, quarantine_path FROM findings WHERE id = ?", (finding_id,)
    ).fetchone()
    if not row:
        conn.close()
        return None
    file_path, existing_q = row
    if existing_q:
        conn.close()
        return existing_q
    if not os.path.exists(file_path):
        conn.close()
        return None

    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    safe_name = file_path.replace("/", "_").lstrip("_")
    q_path = os.path.join(QUARANTINE_DIR, f"{finding_id}_{safe_name}")
    os.rename(file_path, q_path)
    os.chmod(q_path, 0o000)

    conn.execute("UPDATE findings SET quarantine_path = ? WHERE id = ?", (q_path, finding_id))
    _bump_daily_stat(conn, time.strftime("%Y-%m-%d", time.gmtime()), quarantined=1)
    conn.commit()
    conn.close()
    return q_path


def restore_file(finding_id):
    """Moves a quarantined file back to its original location."""
    conn = _connect()
    row = conn.execute(
        "SELECT file_path, quarantine_path FROM findings WHERE id = ?", (finding_id,)
    ).fetchone()
    if not row or not row[1]:
        conn.close()
        return False
    file_path, q_path = row
    if not os.path.exists(q_path):
        conn.close()
        return False
    os.chmod(q_path, 0o644)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    os.rename(q_path, file_path)
    conn.execute("UPDATE findings SET quarantine_path = NULL WHERE id = ?", (finding_id,))
    conn.commit()
    conn.close()
    return True


def delete_quarantined(finding_id):
    """Permanently deletes a quarantined file."""
    conn = _connect()
    row = conn.execute(
        "SELECT quarantine_path FROM findings WHERE id = ?", (finding_id,)
    ).fetchone()
    if not row or not row[0]:
        conn.close()
        return False
    q_path = row[0]
    if os.path.exists(q_path):
        os.remove(q_path)
    conn.execute("UPDATE findings SET quarantine_path = ? WHERE id = ?", ("__deleted__", finding_id))
    conn.commit()
    conn.close()
    return True


def _bump_daily_stat(conn, day, **deltas):
    """Incrementally updates one day's row in daily_stats - same spirit
    as cxs's own cxsscan_counters/cxswatch_counters (one row per day,
    updated as things happen rather than recomputed from raw rows every
    time stats are viewed - cheap at any scale, unlike a GROUP BY over
    the whole scans table once it's years deep)."""
    conn.execute("INSERT INTO daily_stats (date) VALUES (?) ON CONFLICT(date) DO NOTHING", (day,))
    for col, delta in deltas.items():
        conn.execute(f"UPDATE daily_stats SET {col} = {col} + ? WHERE date = ?", (delta, day))


def rebuild_daily_stats():
    """Recomputes daily_stats from scratch out of the raw scans/findings
    tables - for backfilling history that predates this table (e.g.
    scans already in the db before this feature existed), or repairing
    it if it's ever gotten out of sync. Safe to re-run any time."""
    conn = _connect()
    conn.execute("DELETE FROM daily_stats")
    for day, scan_count, files_scanned, hits, total_duration, duration_count in conn.execute(
        "SELECT date(started_at, 'unixepoch'), COUNT(*), SUM(files_scanned), SUM(hits), "
        "       SUM(duration), COUNT(duration) "
        "FROM scans GROUP BY date(started_at, 'unixepoch')"
    ).fetchall():
        conn.execute(
            "INSERT INTO daily_stats (date, scan_count, files_scanned, hits, total_duration, duration_count) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (day, scan_count, files_scanned or 0, hits or 0, total_duration or 0, duration_count),
        )
    for day, quarantined in conn.execute(
        "SELECT date(s.started_at, 'unixepoch'), COUNT(*) FROM findings f "
        "JOIN scans s ON s.id = f.scan_id "
        "WHERE f.quarantine_path IS NOT NULL AND f.quarantine_path != '__deleted__' "
        "GROUP BY date(s.started_at, 'unixepoch')"
    ).fetchall():
        _bump_daily_stat(conn, day, quarantined=quarantined)
    conn.commit()
    conn.close()


def daily_stats(days=30):
    """Returns (date, scan_count, files_scanned, hits, quarantined,
    avg_duration) tuples, oldest first, straight from the daily_stats
    table - no aggregation at read time. Only includes days a scan
    actually happened on - see daily_stats_filled() for a gap-free
    series (e.g. for a chart, where a day with nothing to show still
    needs to occupy its place on the axis)."""
    conn = _connect()
    rows = conn.execute(
        "SELECT date, scan_count, files_scanned, hits, quarantined, "
        "       CASE WHEN duration_count > 0 THEN total_duration / duration_count ELSE NULL END "
        "FROM daily_stats WHERE date >= date('now', ?) ORDER BY date",
        (f"-{int(days)} days",),
    ).fetchall()
    conn.close()
    return rows


def daily_stats_filled(days=30):
    """Same as daily_stats(), but with one row per calendar day in the
    requested window regardless of whether anything happened - asking
    for 30 days should always show 30 days, not just however many
    happened to have a scan recorded."""
    by_date = {row[0]: row for row in daily_stats(days)}
    today = datetime.date.today()
    result = []
    for offset in range(int(days) - 1, -1, -1):
        day = (today - datetime.timedelta(days=offset)).isoformat()
        result.append(by_date.get(day, (day, 0, 0, 0, 0, None)))
    return result


def record_modsec_count(date, count):
    """Upserts (overwrites, not increments) one day's mod_security block
    count - called once daily by cron with that day's total, not
    incrementally per-block like record_scan_result(), since the source
    (grepping the current log) is re-counted from scratch each time
    rather than tailed incrementally."""
    conn = _connect()
    conn.execute(
        "INSERT INTO modsec_daily_stats (date, blocks) VALUES (?, ?) "
        "ON CONFLICT(date) DO UPDATE SET blocks = excluded.blocks",
        (date, count),
    )
    conn.commit()
    conn.close()


def modsec_daily_stats_filled(days=30):
    """Same gap-filling shape as daily_stats_filled() - one (date, blocks)
    row per calendar day in the window, 0 for any day with no recorded
    count (nothing happened, or cron hadn't run yet that far back)."""
    conn = _connect()
    rows = conn.execute(
        "SELECT date, blocks FROM modsec_daily_stats WHERE date >= date('now', ?) ORDER BY date",
        (f"-{int(days)} days",),
    ).fetchall()
    conn.close()
    by_date = {row[0]: row[1] for row in rows}
    today = datetime.date.today()
    result = []
    for offset in range(int(days) - 1, -1, -1):
        day = (today - datetime.timedelta(days=offset)).isoformat()
        result.append((day, by_date.get(day, 0)))
    return result


def recent_scans(limit=50):
    conn = _connect()
    rows = conn.execute(
        "SELECT id, started_at, path, files_scanned, hits, duration, load_avg FROM scans ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def findings_for_scan(scan_id):
    conn = _connect()
    rows = conn.execute(
        "SELECT id, file_path, rule_name, quarantine_path FROM findings WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()
    conn.close()
    return rows


def finding_by_id(finding_id):
    """For the "View" page - a user looking at a bare rule name (or a
    migrated custom-rule pattern) wanting to see the actual matched
    content before deciding whether a finding is a false positive.
    Returns (file_path, rule_name, quarantine_path, size) or None."""
    conn = _connect()
    row = conn.execute(
        "SELECT file_path, rule_name, quarantine_path, size FROM findings WHERE id = ?",
        (finding_id,),
    ).fetchone()
    conn.close()
    return row


def derive_user(file_path, accounts_dir=None):
    """Best-effort account/user name for a finding - cxs's own UI shows
    this as a column (derived from its own accounts-mode path layout,
    not a separately stored field), so we do the same rather than add
    another column: file_path="/home/someuser/public_html/x.php" with
    accounts_dir="/home" -> "someuser". None if file_path doesn't start
    under accounts_dir."""
    accounts_dir = (accounts_dir or os.environ.get("OPENXS_ACCOUNTS_DIR", "/home")).rstrip("/")
    if not file_path.startswith(accounts_dir + "/"):
        return None
    rest = file_path[len(accounts_dir) + 1:]
    user = rest.split("/", 1)[0]
    return user or None


def derive_source(scan_path):
    """Which mechanism found this - cxs's own UI shows "CLI"/"cxsWatch"/
    "Other" per finding; same idea, our own mechanism names. scan_path
    is the scans.path value record_scan() was called with."""
    if scan_path == "migrated from cxs" or scan_path == "migrated from cxs (historical logs)":
        return "Migrated"
    if scan_path.startswith("watch:"):
        return "Watch"
    return "Scan"


# Mirrors pmf_scan.categorize()'s suffix convention - duplicated here
# (not imported) to keep this module dependency-free of pmf_scan.py;
# keep both in sync if a new category/suffix is ever added.
_CATEGORY_SQL = {
    "virus": "f.rule_name LIKE '%(ClamAV)'",
    "maldet": "f.rule_name LIKE '%(maldet)'",
    "oldversion": "f.rule_name LIKE '%(oldversion)'",
    "fs": "f.rule_name IN ('SUID file', 'world-writable directory', 'symlink', 'socket', "
          "'core dump file', 'Linux binary or executable file', 'Windows binary or executable file', "
          "'hidden directory owned by nobody')",
    "yara_exploit": "f.rule_name LIKE '%Known exploit%'",
    "yara_heuristic": "f.rule_name NOT LIKE '%(ClamAV)' AND f.rule_name NOT LIKE '%(maldet)' AND "
            "f.rule_name NOT LIKE '%(oldversion)' AND f.rule_name NOT LIKE '%Known exploit%' AND "
            "f.rule_name NOT IN ('SUID file', "
            "'world-writable directory', 'symlink', 'socket', 'core dump file', "
            "'Linux binary or executable file', 'Windows binary or executable file', "
            "'hidden directory owned by nobody')",
}


def search_findings(category=None, search=None, limit=50, offset=0, sort="date", order="desc"):
    """Unified findings browser query (cxs's own tabbed All/Exploits/
    Virus/Old Versions/... view, which this mirrors) - every finding
    ever recorded, not just quarantined ones, with its scan's date and
    path for derive_user()/derive_source(). category: one of
    _CATEGORY_SQL's keys, or None for everything. search: substring
    match against the file path, case-insensitive. sort/order: same
    FINDING_SORT_COLUMNS as quarantined_files() - plain id order isn't
    date order for a bulk historical import."""
    conn = _connect()
    where = []
    params = []
    if category and category in _CATEGORY_SQL:
        where.append(_CATEGORY_SQL[category])
    if search:
        where.append("f.file_path LIKE ?")
        params.append(f"%{search}%")
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    sort_col = FINDING_SORT_COLUMNS.get(sort, FINDING_SORT_COLUMNS["date"])
    sort_dir = "ASC" if order == "asc" else "DESC"
    query = (
        "SELECT f.id, f.file_path, f.rule_name, f.quarantine_path, f.size, s.started_at, s.path "
        "FROM findings f JOIN scans s ON s.id = f.scan_id "
        f"{where_sql} ORDER BY {sort_col} {sort_dir}, f.id {sort_dir} LIMIT ? OFFSET ?"
    )
    rows = conn.execute(query, (*params, limit, offset)).fetchall()
    count = conn.execute(
        f"SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id {where_sql}", params
    ).fetchone()[0]
    conn.close()
    return rows, count


def import_quarantined_finding(file_path, quarantine_src_path, rule_name, quarantined_at=None):
    """For migrate_from_cxs.py: registers a file that's ALREADY sitting in
    some other tool's quarantine (not a live scan hit) so it shows up in
    OpenXS's own Quarantine view and can be restored/deleted through the
    normal UI from then on. Copies the file into OPENXS_QUARANTINE using
    quarantine_file()'s own naming convention ({finding_id}_{safe_name})
    and chmod 000, for the same restore_file()/delete_quarantined()
    invariants to hold. Returns the new quarantine path."""
    conn = _connect()
    started_at = quarantined_at or time.time()
    scan_id = conn.execute(
        "INSERT INTO scans (started_at, path, files_scanned, hits) VALUES (?, ?, 1, 1)",
        (started_at, "migrated from cxs"),
    ).lastrowid
    try:
        size = os.path.getsize(quarantine_src_path)
    except OSError:
        size = None
    finding_id = conn.execute(
        "INSERT INTO findings (scan_id, file_path, rule_name, size) VALUES (?, ?, ?, ?)",
        (scan_id, file_path, rule_name, size),
    ).lastrowid

    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    safe_name = file_path.replace("/", "_").lstrip("_")
    q_path = os.path.join(QUARANTINE_DIR, f"{finding_id}_{safe_name}")
    os.rename(quarantine_src_path, q_path)
    os.chmod(q_path, 0o000)

    conn.execute("UPDATE findings SET quarantine_path = ? WHERE id = ?", (q_path, finding_id))
    # A historical import, not a live action happening now - credited to
    # its real (quarantined_at) day, not today, unlike quarantine_file()'s
    # live case above.
    day = time.strftime("%Y-%m-%d", time.gmtime(started_at))
    _bump_daily_stat(conn, day, scan_count=1, files_scanned=1, hits=1, quarantined=1)
    conn.commit()
    conn.close()
    return q_path


FINDING_SORT_COLUMNS = {
    "date": "s.started_at",
    "path": "f.file_path",
    "size": "f.size",
    "rule": "f.rule_name",
}


def quarantined_files(limit=50, offset=0, sort="date", order="desc"):
    """Paginated - found for real after migrating cxs's own quarantine
    (6438 files): rendering every row in one unpaginated HTML page (the
    Webmin UI's own quarantine view) was enough to hang a browser tab
    outright. limit=None removes the cap, for scripts that genuinely
    need every row (e.g. migrate_from_cxs.py never calls this at all -
    it writes directly, so this only ever affects the UI).

    Returns (id, file_path, rule_name, quarantine_path, quarantined_at,
    size, scan_path) - the date comes from the parent scan's
    started_at, which for a live quarantine_file() call is "now"
    (close enough) and for import_quarantined_finding() is the real
    historical timestamp recovered from cxs's own .restore4 sidecar,
    not today's import date - findings.quarantined_at of its own
    doesn't exist, this was missing from the UI entirely until asked
    for. size/scan_path are for derive_user()/derive_source(), same
    User/Source columns findings.cgi already has - the quarantine view
    is findings.cgi filtered to one status, so it shouldn't show less.

    sort/order: default is date, newest first - plain f.id DESC (the
    previous default) happened to equal "newest first" for live
    quarantine actions, but not for a historical bulk import like the
    one above - insertion order there isn't chronological order."""
    conn = _connect()
    sort_col = FINDING_SORT_COLUMNS.get(sort, FINDING_SORT_COLUMNS["date"])
    sort_dir = "ASC" if order == "asc" else "DESC"
    query = ("SELECT f.id, f.file_path, f.rule_name, f.quarantine_path, s.started_at, f.size, s.path "
             "FROM findings f JOIN scans s ON s.id = f.scan_id "
             "WHERE f.quarantine_path IS NOT NULL AND f.quarantine_path != '__deleted__' "
             f"ORDER BY {sort_col} {sort_dir}, f.id {sort_dir}")
    params = ()
    if limit is not None:
        query += " LIMIT ? OFFSET ?"
        params = (limit, offset)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows


def quarantined_files_count():
    conn = _connect()
    count = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE quarantine_path IS NOT NULL AND quarantine_path != '__deleted__'"
    ).fetchone()[0]
    conn.close()
    return count
