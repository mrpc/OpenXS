import sys

sys.path.insert(0, "tools")
import wp_db_scan as wds


class FakeMatch:
    def __init__(self, rule):
        self.rule = rule


class FakeRules:
    """Matches "EVIL" (case-sensitive) anywhere in the data, plus always
    "fires" IsWhitelisted/IsPhp the way the real meta-rules never
    actually do in yara-python's results - exercising that the code
    under test filters them out anyway, not relying on YARA's own
    private-rule semantics to do it."""
    def match(self, data):
        hits = [FakeMatch("IsPhp")]
        if b"EVIL" in data:
            hits.append(FakeMatch("DangerousPhp"))
        return hits


def test_parse_wp_config_reads_standard_constants(tmp_path):
    wp_root = tmp_path
    (wp_root / "wp-config.php").write_text(
        "<?php\n"
        "define('DB_NAME', 'wp_site');\n"
        "define('DB_USER', 'wp_user');\n"
        "define('DB_PASSWORD', 'hunter2');\n"
        "define('DB_HOST', 'localhost');\n"
        "$table_prefix = 'wp_';\n"
    )
    cfg = wds.parse_wp_config(str(wp_root))
    assert cfg == {"name": "wp_site", "user": "wp_user", "password": "hunter2",
                   "host": "localhost", "prefix": "wp_"}


def test_parse_wp_config_defaults_prefix_when_missing(tmp_path):
    wp_root = tmp_path
    (wp_root / "wp-config.php").write_text(
        "<?php\n"
        "define('DB_NAME', 'wp_site');\n"
        "define('DB_USER', 'wp_user');\n"
        "define('DB_PASSWORD', 'hunter2');\n"
        "define('DB_HOST', 'localhost');\n"
    )
    cfg = wds.parse_wp_config(str(wp_root))
    assert cfg["prefix"] == "wp_"


def test_parse_wp_config_none_when_incomplete(tmp_path):
    wp_root = tmp_path
    (wp_root / "wp-config.php").write_text("<?php\ndefine('DB_NAME', 'wp_site');\n")
    assert wds.parse_wp_config(str(wp_root)) is None


def test_parse_wp_config_none_when_missing_file(tmp_path):
    assert wds.parse_wp_config(str(tmp_path)) is None


def test_load_db_scan_excludes_parses_plain_substrings(tmp_path):
    f = tmp_path / "db_scan_exclude"
    f.write_text("# comment\n\n/home/someuser\nparked-domain.gr\n")
    assert wds.load_db_scan_excludes(str(f)) == ["/home/someuser", "parked-domain.gr"]


def test_load_db_scan_excludes_empty_when_missing(tmp_path):
    assert wds.load_db_scan_excludes(str(tmp_path / "no-such-file")) == []


def test_is_db_scan_excluded_matches_substring():
    patterns = ["/home/someuser", "parked-domain.gr"]
    assert wds.is_db_scan_excluded("/home/someuser/public_html", patterns)
    assert not wds.is_db_scan_excluded("/home/otheruser/public_html", patterns)


def test_webmin_mysql_root_credentials_parses_config(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    cfg.write_text("date_subs=0\nlogin=root\npass=s3cret\nmysqlshow=/usr/bin/mysqlshow\n")
    monkeypatch.setattr(wds, "WEBMIN_MYSQL_CONFIG", str(cfg))
    assert wds.webmin_mysql_root_credentials() == ("root", "s3cret")


def test_webmin_mysql_root_credentials_none_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(wds, "WEBMIN_MYSQL_CONFIG", str(tmp_path / "no-such-file"))
    assert wds.webmin_mysql_root_credentials() is None


def test_webmin_mysql_root_credentials_none_when_incomplete(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    cfg.write_text("login=root\n")  # no pass=
    monkeypatch.setattr(wds, "WEBMIN_MYSQL_CONFIG", str(cfg))
    assert wds.webmin_mysql_root_credentials() is None


def test_scan_wp_database_prefers_webmin_root_credentials(tmp_path, monkeypatch):
    wp_root = tmp_path
    (wp_root / "wp-config.php").write_text(
        "<?php\n"
        "define('DB_NAME', 'wp_site');\n"
        "define('DB_USER', 'wp_user');\n"
        "define('DB_PASSWORD', 'site-own-password');\n"
        "define('DB_HOST', 'localhost');\n"
    )
    monkeypatch.setattr(wds, "webmin_mysql_root_credentials", lambda: ("root", "webmin-root-password"))
    captured = {}

    def fake_run_query(db_config, query, timeout=30):
        captured["db_config"] = db_config
        return None
    monkeypatch.setattr(wds, "run_query", fake_run_query)

    wds.scan_wp_database(str(wp_root), FakeRules())
    assert captured["db_config"]["user"] == "root"
    assert captured["db_config"]["password"] == "webmin-root-password"
    assert captured["db_config"]["name"] == "wp_site"  # DB name/host still from wp-config.php


def test_split_host_plain():
    assert wds._split_host("localhost") == ("localhost", None, None)


def test_split_host_with_port():
    assert wds._split_host("127.0.0.1:3307") == ("127.0.0.1", "3307", None)


def test_split_host_with_socket_after_colon():
    assert wds._split_host("localhost:/var/run/mysqld/mysqld10.sock") == ("localhost", None, "/var/run/mysqld/mysqld10.sock")


def test_split_host_bare_socket_path():
    assert wds._split_host("/var/run/mysqld/mysqld.sock") == ("localhost", None, "/var/run/mysqld/mysqld.sock")


def test_run_query_returns_none_on_nonzero_exit(monkeypatch):
    class FakeResult:
        returncode = 1
        stdout = b""
    monkeypatch.setattr(wds.subprocess, "run", lambda *a, **k: FakeResult())
    assert wds.run_query({"name": "x", "user": "u", "password": "p", "host": "localhost"}, "SELECT 1") is None


def test_run_query_returns_none_on_exception(monkeypatch):
    def boom(*a, **k):
        raise OSError("mysql not found")
    monkeypatch.setattr(wds.subprocess, "run", boom)
    assert wds.run_query({"name": "x", "user": "u", "password": "p", "host": "localhost"}, "SELECT 1") is None


def test_run_query_parses_tab_separated_rows(monkeypatch):
    class FakeResult:
        returncode = 0
        stdout = b"1\thello\n2\tworld\n"
    monkeypatch.setattr(wds.subprocess, "run", lambda *a, **k: FakeResult())
    rows = wds.run_query({"name": "x", "user": "u", "password": "p", "host": "localhost"}, "SELECT 1")
    assert rows == [["1", "hello"], ["2", "world"]]


def test_run_query_unescapes_embedded_newlines_in_a_field(monkeypatch):
    # Found live 2026-10-27: a real multi-paragraph post's content has
    # literal newlines in it - mysql's own batch-mode escaping turns a
    # real "\n" byte into the two literal characters backslash-n in its
    # stdout (unless --raw is passed, which this deliberately no longer
    # does), so the row/column split must reverse that same escaping.
    class FakeResult:
        returncode = 0
        stdout = b"1\tfirst line\\nsecond line\\nthird line\n2\tno newlines here\n"
    monkeypatch.setattr(wds.subprocess, "run", lambda *a, **k: FakeResult())
    rows = wds.run_query({"name": "x", "user": "u", "password": "p", "host": "localhost"}, "SELECT 1")
    assert rows == [["1", "first line\nsecond line\nthird line"], ["2", "no newlines here"]]


def test_run_query_unescapes_tabs_and_backslashes_in_a_field(monkeypatch):
    class FakeResult:
        returncode = 0
        stdout = b"1\ta\\tb\\\\c\n"
    monkeypatch.setattr(wds.subprocess, "run", lambda *a, **k: FakeResult())
    rows = wds.run_query({"name": "x", "user": "u", "password": "p", "host": "localhost"}, "SELECT 1")
    assert rows == [["1", "a\tb\\c"]]


def test_run_query_does_not_pass_raw_flag(monkeypatch):
    captured = {}
    class FakeResult:
        returncode = 0
        stdout = b""
    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakeResult()
    monkeypatch.setattr(wds.subprocess, "run", fake_run)
    wds.run_query({"name": "x", "user": "u", "password": "p", "host": "localhost"}, "SELECT 1")
    assert "--raw" not in captured["cmd"]


def test_run_query_never_passes_password_on_argv(monkeypatch):
    captured = {}
    class FakeResult:
        returncode = 0
        stdout = b""
    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakeResult()
    monkeypatch.setattr(wds.subprocess, "run", fake_run)
    wds.run_query({"name": "x", "user": "u", "password": "super-secret", "host": "localhost"}, "SELECT 1")
    assert "super-secret" not in captured["cmd"]
    assert not any("super-secret" in str(a) for a in captured["cmd"])


def test_match_content_filters_meta_rules_and_finds_real_hit():
    rules = FakeRules()
    hits = wds._match_content(rules, "normal <?php EVIL(); ?>", "some.label")
    assert hits == [("DangerousPhp", "some.label")]


def test_match_content_empty_for_clean_content():
    rules = FakeRules()
    assert wds._match_content(rules, "perfectly normal text", "some.label") == []


def test_match_content_skips_oversized_content():
    rules = FakeRules()
    huge = "EVIL" + ("x" * wds.MAX_ROW_BYTES)
    assert wds._match_content(rules, huge, "some.label") == []


def test_scan_wp_database_returns_empty_without_config(tmp_path):
    assert wds.scan_wp_database(str(tmp_path), FakeRules()) == []


def test_scan_wp_database_finds_hits_in_posts_and_comments(tmp_path, monkeypatch):
    wp_root = tmp_path
    (wp_root / "wp-config.php").write_text(
        "<?php\n"
        "define('DB_NAME', 'wp_site');\n"
        "define('DB_USER', 'wp_user');\n"
        "define('DB_PASSWORD', 'hunter2');\n"
        "define('DB_HOST', 'localhost');\n"
    )

    def fake_run_query(db_config, query, timeout=30):
        if "posts" in query:
            return [["42", "Normal title", "body with EVIL() injected"]]
        if "comments" in query:
            return [["7", "spam comment EVIL()"]]
        return None
    monkeypatch.setattr(wds, "run_query", fake_run_query)

    results = wds.scan_wp_database(str(wp_root), FakeRules())
    labels = {label for label, _rule in results}
    assert "wp_posts.post_content (post ID 42)" in labels
    assert "wp_comments.comment_content (comment ID 7)" in labels
    assert all(rule == "DangerousPhp" for _label, rule in results)


def test_scan_wp_database_handles_unreachable_db(tmp_path, monkeypatch):
    wp_root = tmp_path
    (wp_root / "wp-config.php").write_text(
        "<?php\n"
        "define('DB_NAME', 'wp_site');\n"
        "define('DB_USER', 'wp_user');\n"
        "define('DB_PASSWORD', 'hunter2');\n"
        "define('DB_HOST', 'localhost');\n"
    )
    monkeypatch.setattr(wds, "run_query", lambda *a, **k: None)
    assert wds.scan_wp_database(str(wp_root), FakeRules()) == []
