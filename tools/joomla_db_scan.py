"""Scans a Joomla (or classic Mambo/Joomla 1.0) install's own database
for malicious content injected directly into the database - same idea
and mechanism as wp_db_scan.py (see its docstring for the full
reasoning), whose shared DB-connectivity helpers (run_query(),
webmin_mysql_root_credentials(), the YARA-matching helper) this module
reuses rather than re-implementing.

v1 scope: {prefix}content (title/introtext/fulltext - articles) and
{prefix}modules (title/content - custom HTML modules, a common
injection target since they render raw on every page). {prefix}menu
link URLs and other tables are deliberately deferred, same reasoning
as wp_db_scan.py's own deferred wp_options/wp_postmeta.

Column names actually used by {prefix}content vary across Joomla's own
history (Mambo/Joomla 1.0 had "text" where 1.5+ split it into
"introtext"/"fulltext") - rather than hardcoding one schema version,
this reads the table's real columns first (SHOW COLUMNS) and only
selects whichever of the known candidate names actually exist.
"""
import os
import re

import wp_db_scan

MOS_CONFIG_RE = re.compile(
    r"\$mosConfig_(host|user|password|db|dbprefix)\s*=\s*['\"](.*?)['\"]\s*;"
)
JCONFIG_RE = re.compile(
    r"(?:public|var)\s+\$(host|user|password|db|dbprefix)\s*=\s*['\"](.*?)['\"]\s*;"
)

CONTENT_TEXT_COLUMNS = ("title", "introtext", "fulltext", "text")
MODULE_TEXT_COLUMNS = ("title", "content")


def parse_joomla_config(joomla_root):
    """{"name", "user", "password", "host", "prefix"} from
    configuration.php, or None if it's missing or doesn't define all
    four DB fields as plain literal strings. Handles both the classic
    Mambo/Joomla 1.0 $mosConfig_* global-variable style and the
    JConfig-class ($host/$user/...) style every version since Joomla
    1.5 uses."""
    path = os.path.join(joomla_root, "configuration.php")
    try:
        with open(path, errors="replace") as f:
            content = f.read()
    except OSError:
        return None
    fields = {}
    for m in MOS_CONFIG_RE.finditer(content):
        fields.setdefault(m.group(1), m.group(2))
    if "db" not in fields:
        for m in JCONFIG_RE.finditer(content):
            fields.setdefault(m.group(1), m.group(2))
    if not all(k in fields for k in ("host", "user", "password", "db")):
        return None
    return {
        "name": fields["db"],
        "user": fields["user"],
        "password": fields["password"],
        "host": fields["host"],
        "prefix": fields.get("dbprefix", "jos_"),
    }


def _existing_columns(db_config, table):
    rows = wp_db_scan.run_query(db_config, f"SHOW COLUMNS FROM {table}")
    if not rows:
        return set()
    return {row[0] for row in rows if row}


def scan_joomla_database(joomla_root, rules):
    """[(label, rule_name)] - see wp_db_scan.scan_wp_database()'s
    docstring for the overall shape/guarantees (same [] on an
    unreachable DB, same label format for a findings-table file_path
    that's readable even with no real file behind it)."""
    db_config = parse_joomla_config(joomla_root)
    if not db_config:
        return []
    prefix = db_config["prefix"]
    results = []

    content_table = f"{prefix}content"
    content_cols = [c for c in CONTENT_TEXT_COLUMNS if c in _existing_columns(db_config, content_table)]
    if content_cols:
        rows = wp_db_scan.run_query(
            db_config, f"SELECT id, {', '.join(content_cols)} FROM {content_table}"
        )
        if rows:
            for row in rows:
                if len(row) != len(content_cols) + 1:
                    continue
                article_id = row[0]
                for col, value in zip(content_cols, row[1:]):
                    label = f"{content_table}.{col} (article ID {article_id})"
                    for rule, matched_label in wp_db_scan._match_content(rules, value, label):
                        results.append((matched_label, rule))

    modules_table = f"{prefix}modules"
    module_cols = [c for c in MODULE_TEXT_COLUMNS if c in _existing_columns(db_config, modules_table)]
    if module_cols:
        rows = wp_db_scan.run_query(
            db_config, f"SELECT id, {', '.join(module_cols)} FROM {modules_table}"
        )
        if rows:
            for row in rows:
                if len(row) != len(module_cols) + 1:
                    continue
                module_id = row[0]
                for col, value in zip(module_cols, row[1:]):
                    label = f"{modules_table}.{col} (module ID {module_id})"
                    for rule, matched_label in wp_db_scan._match_content(rules, value, label):
                        results.append((matched_label, rule))

    return results
