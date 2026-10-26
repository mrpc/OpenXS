"""Scans a WordPress install's own database for malicious content
injected directly into the DB - a 2+ year compromise found live on
mrpc.pramnos.net (2026-10-25) lived entirely in wp_posts as a published
WPCode/Insert-Headers-and-Footers snippet (cookie-gated admin-user
creation, C2-proxied content injection) and never touched the
filesystem at all, so no amount of file-based scanning could ever have
caught it (see README.md's roadmap note on this).

Reuses the exact same compiled YARA ruleset pmf_scan.py already uses
for files - yara-python's Rules.match() accepts raw bytes directly
(data=...), not just a file path, so this is no separate detection
logic to maintain, just a different content source.

Connects using the SAME credentials wp-config.php already has (the
site's own DB user, read from the site's own filesystem - never a
separate account we'd have to provision). Every query here is a
read-only SELECT. Uses the `mysql` CLI (not a Python DB driver, to
avoid a new dependency these servers may not otherwise have) with
credentials passed via a temp --defaults-extra-file, never as a CLI
argument (which would otherwise leak the password into `ps`/process
listings for anyone else on the box).

Opt-in, off by default (OPENXS_DB_SCAN_ENABLED) - reading a site's own
DB credentials and connecting to its live database is a meaningfully
bigger step than anything file-scanning-only does, so this doesn't
run until a server operator deliberately turns it on.

v1 scope: wp_posts (post_title/post_content, any type/status) and
wp_comments (comment_content) - the two places real injected-content
compromises are actually known to live. wp_options (highly variable in
size/shape - serialized widget/customizer data, transients that change
constantly) and wp_postmeta/wp_usermeta (huge row counts on any site
with real traffic/media) are deliberately deferred rather than
guessed at without first seeing what the first two tables turn up on
the real fleet.
"""
import os
import re
import subprocess
import tempfile

WEBMIN_MYSQL_CONFIG = os.environ.get("OPENXS_WEBMIN_MYSQL_CONFIG", "/etc/webmin/mysql/config")

DB_DEFINE_RE = re.compile(
    r"define\s*\(\s*['\"]DB_(NAME|USER|PASSWORD|HOST)['\"]\s*,\s*['\"](.*?)['\"]\s*\)", re.DOTALL
)
TABLE_PREFIX_RE = re.compile(r"\$table_prefix\s*=\s*['\"](.*?)['\"]")

MAX_ROW_BYTES = 2 * 1024 * 1024  # a legitimate post/comment is never anywhere close to this


def parse_wp_config(wp_root):
    """{"name", "user", "password", "host", "prefix"} from wp-config.php,
    or None if it's missing or doesn't define all four DB_* constants as
    plain literal strings (a config that builds them from a variable,
    getenv(), an include, ...) isn't something this regex-only parser
    can safely handle - same tradeoff run_scheduled_scan.sh's own
    plain-KEY=value config parsing makes, deliberately not a real PHP
    interpreter."""
    path = os.path.join(wp_root, "wp-config.php")
    try:
        with open(path, errors="replace") as f:
            content = f.read()
    except OSError:
        return None
    db = {}
    for m in DB_DEFINE_RE.finditer(content):
        db.setdefault(m.group(1), m.group(2))
    if not all(k in db for k in ("NAME", "USER", "PASSWORD", "HOST")):
        return None
    prefix_m = TABLE_PREFIX_RE.search(content)
    return {
        "name": db["NAME"],
        "user": db["USER"],
        "password": db["PASSWORD"],
        "host": db["HOST"],
        "prefix": prefix_m.group(1) if prefix_m else "wp_",
    }


def webmin_mysql_root_credentials():
    """(user, password) from Webmin's own stored MySQL root login
    (/etc/webmin/mysql/config - the exact same credentials the "MySQL
    Database Server" Webmin module already uses, plain KEY=value, root-
    readable only), or None if that file doesn't exist or doesn't have
    both. Preferred over a site's own wp-config.php DB_USER/DB_PASSWORD
    when available - one set of credentials per server to maintain
    instead of potentially hundreds of different per-site ones, and
    works even for a site whose wp-config.php pulls its DB password from
    somewhere parse_wp_config() can't follow (env var, a second include,
    ...) as long as DB_NAME/DB_HOST are still plain literals there."""
    try:
        with open(WEBMIN_MYSQL_CONFIG, errors="replace") as f:
            lines = dict(
                line.strip().split("=", 1)
                for line in f if "=" in line and not line.strip().startswith("#")
            )
    except OSError:
        return None
    user = lines.get("login")
    password = lines.get("pass")
    if not user or not password:
        return None
    return user, password


def _split_host(host):
    """(host, port, socket) - DB_HOST commonly carries a port
    ("localhost:3306") or, on Virtualmin/cPanel-style setups, a Unix
    socket path ("localhost:/var/run/mysqld/mysqld10.sock")."""
    if host.startswith("/"):
        return "localhost", None, host
    if ":" in host:
        h, _, rest = host.partition(":")
        if rest.startswith("/"):
            return h, None, rest
        return h, rest, None
    return host, None, None


def run_query(db_config, query, timeout=30):
    """Rows (each a list of column strings) from a single read-only
    query against this site's own database, or None on any failure
    (unreachable, bad credentials, timeout, mysql CLI missing) -
    callers treat None the same as "found nothing to scan", never as
    something to crash a whole scan run over."""
    host, port, socket = _split_host(db_config["host"])
    cnf_fd, cnf_path = tempfile.mkstemp(suffix=".cnf")
    try:
        with os.fdopen(cnf_fd, "w") as cnf:
            cnf.write("[client]\n")
            cnf.write(f"user={db_config['user']}\n")
            cnf.write(f"password={db_config['password']}\n")
            if socket:
                cnf.write(f"socket={socket}\n")
            else:
                cnf.write(f"host={host}\n")
                if port:
                    cnf.write(f"port={port}\n")
        os.chmod(cnf_path, 0o600)
        cmd = ["mysql", f"--defaults-extra-file={cnf_path}", "--batch", "--raw", "-N",
               db_config["name"], "-e", query]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        rows = []
        for line in result.stdout.decode(errors="replace").split("\n"):
            if line:
                rows.append(line.split("\t"))
        return rows
    finally:
        try:
            os.unlink(cnf_path)
        except OSError:
            pass


def _match_content(rules, content, label):
    """[(rule_name, label)] for every real YARA match against this one
    piece of DB content - "real" meaning the same IsWhitelisted/IsPhp
    meta-rule exclusion pmf_scan.py's own file-scan loop applies (see
    its is_unmodified_core_file()'s docstring on why those never
    actually appear in match results anyway)."""
    if not content or len(content) > MAX_ROW_BYTES:
        return []
    data = content.encode("utf-8", errors="replace")
    try:
        matches = rules.match(data=data)
    except Exception:
        return []
    return [(m.rule, label) for m in matches if m.rule not in ("IsWhitelisted", "IsPhp")]


def scan_wp_database(wp_root, rules):
    """[(label, rule_name)] for every malicious-pattern hit found in
    this WordPress install's own database - label identifies exactly
    which row (e.g. "wp_posts.post_content (post ID 42)"), for a
    findings-table file_path that's readable even though there's no
    actual file behind it. [] (not None) if the DB is unreachable or
    wp-config.php couldn't be parsed - a scan that can't reach this
    site's database is not itself a finding."""
    db_config = parse_wp_config(wp_root)
    if not db_config:
        return []
    root_creds = webmin_mysql_root_credentials()
    if root_creds:
        db_config = dict(db_config)
        db_config["user"], db_config["password"] = root_creds
    prefix = db_config["prefix"]
    results = []

    posts = run_query(
        db_config,
        f"SELECT ID, post_title, post_content FROM {prefix}posts",
    )
    if posts:
        for row in posts:
            if len(row) != 3:
                continue
            post_id, title, body = row
            for rule, label in _match_content(rules, title, f"{prefix}posts.post_title (post ID {post_id})"):
                results.append((label, rule))
            for rule, label in _match_content(rules, body, f"{prefix}posts.post_content (post ID {post_id})"):
                results.append((label, rule))

    comments = run_query(
        db_config,
        f"SELECT comment_ID, comment_content FROM {prefix}comments",
    )
    if comments:
        for row in comments:
            if len(row) != 2:
                continue
            comment_id, body = row
            for rule, label in _match_content(rules, body, f"{prefix}comments.comment_content (comment ID {comment_id})"):
                results.append((label, rule))

    return results
