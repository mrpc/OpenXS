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
CREATE TABLE IF NOT EXISTS daily_stats (
    date TEXT PRIMARY KEY,
    scan_count INTEGER NOT NULL DEFAULT 0,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    hits INTEGER NOT NULL DEFAULT 0,
    quarantined INTEGER NOT NULL DEFAULT 0,
    total_duration REAL NOT NULL DEFAULT 0,
    duration_count INTEGER NOT NULL DEFAULT 0
);
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
    # Only the first call for this DB_PATH actually runs the schema/
    # migration DDL - cheap already, but no reason to repeat it either.
    if _schema_initialized_for != DB_PATH:
        conn.executescript(SCHEMA)
        # Added after the initial release - ALTER TABLE, not a CREATE
        # TABLE clause, since that only applies to a table that doesn't
        # exist yet and an existing openxs.db already has the old
        # `scans` schema.
        for column in ("duration REAL", "load_avg REAL"):
            try:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass  # already added in a previous run
        _schema_initialized_for = DB_PATH
    return _KeepOpenConnection(conn)


def record_scan(path, files_scanned, findings, duration=None, load_avg=None):
    """findings: list of (file_path, rule_name) tuples"""
    conn = _connect()
    started_at = time.time()
    cur = conn.execute(
        "INSERT INTO scans (started_at, path, files_scanned, hits, duration, load_avg) VALUES (?, ?, ?, ?, ?, ?)",
        (started_at, path, files_scanned, len(findings), duration, load_avg),
    )
    scan_id = cur.lastrowid
    conn.executemany(
        "INSERT INTO findings (scan_id, file_path, rule_name) VALUES (?, ?, ?)",
        [(scan_id, f, r) for f, r in findings],
    )
    day = time.strftime("%Y-%m-%d", time.gmtime(started_at))
    _bump_daily_stat(conn, day, scan_count=1, files_scanned=files_scanned, hits=len(findings),
                      total_duration=duration or 0, duration_count=1 if duration is not None else 0)
    conn.commit()
    conn.close()
    return scan_id


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
    finding_id = conn.execute(
        "INSERT INTO findings (scan_id, file_path, rule_name) VALUES (?, ?, ?)",
        (scan_id, file_path, rule_name),
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


def quarantined_files(limit=50, offset=0):
    """Paginated - found for real after migrating cxs's own quarantine
    (6438 files): rendering every row in one unpaginated HTML page (the
    Webmin UI's own quarantine view) was enough to hang a browser tab
    outright. limit=None removes the cap, for scripts that genuinely
    need every row (e.g. migrate_from_cxs.py never calls this at all -
    it writes directly, so this only ever affects the UI).

    Returns (id, file_path, rule_name, quarantine_path, quarantined_at)
    - the date comes from the parent scan's started_at, which for a
    live quarantine_file() call is "now" (close enough) and for
    import_quarantined_finding() is the real historical timestamp
    recovered from cxs's own .restore4 sidecar, not today's import
    date - findings.quarantined_at of its own doesn't exist, this was
    missing from the UI entirely until asked for."""
    conn = _connect()
    query = ("SELECT f.id, f.file_path, f.rule_name, f.quarantine_path, s.started_at "
             "FROM findings f JOIN scans s ON s.id = f.scan_id "
             "WHERE f.quarantine_path IS NOT NULL AND f.quarantine_path != '__deleted__' "
             "ORDER BY f.id DESC")
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
