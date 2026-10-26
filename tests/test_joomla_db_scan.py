import sys

sys.path.insert(0, "tools")
import joomla_db_scan as jds
import wp_db_scan as wds


class FakeMatch:
    def __init__(self, rule):
        self.rule = rule


class FakeRules:
    def match(self, data):
        hits = [FakeMatch("IsPhp")]
        if b"EVIL" in data:
            hits.append(FakeMatch("DangerousPhp"))
        return hits


def test_parse_joomla_config_mambo_style(tmp_path):
    joomla_root = tmp_path
    (joomla_root / "configuration.php").write_text(
        "<?php\n"
        "$mosConfig_host = 'localhost';\n"
        "$mosConfig_user = 'acme_user';\n"
        "$mosConfig_password = 'hunter2';\n"
        "$mosConfig_db = 'acme_db';\n"
        "$mosConfig_dbprefix = 'jos_';\n"
    )
    cfg = jds.parse_joomla_config(str(joomla_root))
    assert cfg == {"name": "acme_db", "user": "acme_user", "password": "hunter2",
                   "host": "localhost", "prefix": "jos_"}


def test_parse_joomla_config_jconfig_style(tmp_path):
    joomla_root = tmp_path
    (joomla_root / "configuration.php").write_text(
        "<?php\n"
        "class JConfig {\n"
        "\tpublic $host = 'localhost';\n"
        "\tpublic $user = 'joomla_user';\n"
        "\tpublic $password = 'hunter3';\n"
        "\tpublic $db = 'joomla_db';\n"
        "\tpublic $dbprefix = 'jos_';\n"
        "}\n"
    )
    cfg = jds.parse_joomla_config(str(joomla_root))
    assert cfg == {"name": "joomla_db", "user": "joomla_user", "password": "hunter3",
                   "host": "localhost", "prefix": "jos_"}


def test_parse_joomla_config_defaults_prefix(tmp_path):
    joomla_root = tmp_path
    (joomla_root / "configuration.php").write_text(
        "<?php\n"
        "$mosConfig_host = 'localhost';\n"
        "$mosConfig_user = 'u';\n"
        "$mosConfig_password = 'p';\n"
        "$mosConfig_db = 'd';\n"
    )
    cfg = jds.parse_joomla_config(str(joomla_root))
    assert cfg["prefix"] == "jos_"


def test_parse_joomla_config_none_when_incomplete(tmp_path):
    (tmp_path / "configuration.php").write_text("<?php\n$mosConfig_db = 'd';\n")
    assert jds.parse_joomla_config(str(tmp_path)) is None


def test_parse_joomla_config_none_when_missing_file(tmp_path):
    assert jds.parse_joomla_config(str(tmp_path)) is None


def test_scan_joomla_database_returns_empty_without_config(tmp_path):
    assert jds.scan_joomla_database(str(tmp_path), FakeRules()) == []


def test_scan_joomla_database_finds_hits_in_content_and_modules(tmp_path, monkeypatch):
    joomla_root = tmp_path
    (joomla_root / "configuration.php").write_text(
        "<?php\n"
        "$mosConfig_host = 'localhost';\n"
        "$mosConfig_user = 'u';\n"
        "$mosConfig_password = 'p';\n"
        "$mosConfig_db = 'd';\n"
        "$mosConfig_dbprefix = 'jos_';\n"
    )

    def fake_run_query(db_config, query):
        if query.startswith("SHOW COLUMNS FROM jos_content"):
            return [["id"], ["title"], ["introtext"], ["fulltext"]]
        if query.startswith("SHOW COLUMNS FROM jos_modules"):
            return [["id"], ["title"], ["content"]]
        if query.startswith("SELECT id, title, introtext, fulltext FROM jos_content"):
            return [["42", "Normal title", "clean intro", "body with EVIL() injected"]]
        if query.startswith("SELECT id, title, content FROM jos_modules"):
            return [["7", "Banner", "EVIL() in a custom module"]]
        return None
    monkeypatch.setattr(wds, "run_query", fake_run_query)

    results = jds.scan_joomla_database(str(joomla_root), FakeRules())
    labels = {label for label, _rule in results}
    assert "jos_content.fulltext (article ID 42)" in labels
    assert "jos_modules.content (module ID 7)" in labels
    assert all(rule == "DangerousPhp" for _label, rule in results)


def test_scan_joomla_database_skips_missing_tables(tmp_path, monkeypatch):
    joomla_root = tmp_path
    (joomla_root / "configuration.php").write_text(
        "<?php\n"
        "$mosConfig_host = 'localhost';\n"
        "$mosConfig_user = 'u';\n"
        "$mosConfig_password = 'p';\n"
        "$mosConfig_db = 'd';\n"
    )
    monkeypatch.setattr(wds, "run_query", lambda *a, **k: None)
    assert jds.scan_joomla_database(str(joomla_root), FakeRules()) == []
