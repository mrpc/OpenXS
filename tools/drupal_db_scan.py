"""Scans a Drupal 7 install's own database for malicious content
injected directly into the database - same idea and mechanism as
wp_db_scan.py (see its docstring for the full reasoning), whose shared
DB-connectivity helpers (run_query(), webmin_mysql_root_credentials(),
the YARA-matching helper) this module reuses rather than
re-implementing.

v1 scope: field_data_body (node body text - Drupal 7's Field API
storage, not a direct node_revision column the way Drupal 6 had it)
and block_custom (admin-authored custom HTML blocks, rendered raw on
every page they're placed on - a real, known injection target).
variable (serialized site config, a documented PHP-backdoor vector in
Drupal) is deliberately deferred - broad/variable in size and shape,
same reasoning as wp_db_scan.py's own deferred wp_options.
"""
import os
import re

import wp_db_scan

COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
FIELD_RE = re.compile(r"'(database|username|password|host|prefix)'\s*=>\s*'(.*?)'")


def parse_drupal_config(drupal_root):
    """{"name", "user", "password", "host", "prefix"} from
    sites/default/settings.php's real (uncommented) $databases array,
    or None if it's missing or doesn't define all four DB fields as
    plain literal strings. Block comments are stripped first so the
    doc-comment's own example $databases assignments (every real
    settings.php ships several, showing mysql/pgsql/sqlite/replica
    variants) are never mistaken for the real one."""
    path = os.path.join(drupal_root, "sites", "default", "settings.php")
    try:
        with open(path, errors="replace") as f:
            content = f.read()
    except OSError:
        return None
    content = COMMENT_RE.sub("", content)
    m = re.search(r"\$databases\s*=\s*array\s*\(", content)
    if not m:
        return None
    fields = {}
    for fm in FIELD_RE.finditer(content[m.end():]):
        fields.setdefault(fm.group(1), fm.group(2))
    if not all(k in fields for k in ("database", "username", "password", "host")):
        return None
    return {
        "name": fields["database"],
        "user": fields["username"],
        "password": fields["password"],
        "host": fields["host"],
        "prefix": fields.get("prefix", ""),
    }


def scan_drupal_database(drupal_root, rules):
    """[(label, rule_name)] - see wp_db_scan.scan_wp_database()'s
    docstring for the overall shape/guarantees (same [] on an
    unreachable DB, same label format for a findings-table file_path
    that's readable even with no real file behind it)."""
    db_config = parse_drupal_config(drupal_root)
    if not db_config:
        return []
    prefix = db_config["prefix"]
    results = []

    body_table = f"{prefix}field_data_body"
    rows = wp_db_scan.run_query(db_config, f"SELECT entity_id, body_value FROM {body_table}")
    if rows:
        for row in rows:
            if len(row) != 2:
                continue
            entity_id, body = row
            label = f"{body_table}.body_value (entity ID {entity_id})"
            for rule, matched_label in wp_db_scan._match_content(rules, body, label):
                results.append((matched_label, rule))

    block_table = f"{prefix}block_custom"
    rows = wp_db_scan.run_query(db_config, f"SELECT bid, body FROM {block_table}")
    if rows:
        for row in rows:
            if len(row) != 2:
                continue
            bid, body = row
            label = f"{block_table}.body (block ID {bid})"
            for rule, matched_label in wp_db_scan._match_content(rules, body, label):
                results.append((matched_label, rule))

    return results
