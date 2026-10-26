import sys

sys.path.insert(0, "tools")
import drupal_db_scan as dds
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


SETTINGS_PHP = """<?php
/**
 * Example:
 * @code
 *   $databases['default']['default'] = array(
 *     'driver' => 'mysql',
 *     'database' => 'databasename',
 *     'username' => 'username',
 *     'password' => 'password',
 *     'host' => 'localhost',
 *     'prefix' => 'myprefix_',
 *   );
 * @endcode
 */

$databases = array (
  'default' =>
  array (
    'default' =>
    array (
      'database' => 'acme_drupal',
      'username' => 'acme_user',
      'password' => 'hunter2',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
"""


def test_parse_drupal_config_real_settings_php(tmp_path):
    drupal_root = tmp_path
    (drupal_root / "sites" / "default").mkdir(parents=True)
    (drupal_root / "sites" / "default" / "settings.php").write_text(SETTINGS_PHP)
    cfg = dds.parse_drupal_config(str(drupal_root))
    assert cfg == {"name": "acme_drupal", "user": "acme_user", "password": "hunter2",
                   "host": "localhost", "prefix": ""}


def test_parse_drupal_config_none_without_real_assignment(tmp_path):
    drupal_root = tmp_path
    (drupal_root / "sites" / "default").mkdir(parents=True)
    (drupal_root / "sites" / "default" / "settings.php").write_text(
        "<?php\n/**\n * $databases['default']['default'] = array(\n *   'database' => 'x',\n */\n"
    )
    assert dds.parse_drupal_config(str(drupal_root)) is None


def test_parse_drupal_config_none_when_missing_file(tmp_path):
    assert dds.parse_drupal_config(str(tmp_path)) is None


def test_scan_drupal_database_returns_empty_without_config(tmp_path):
    assert dds.scan_drupal_database(str(tmp_path), FakeRules()) == []


def test_scan_drupal_database_finds_hits_in_body_and_blocks(tmp_path, monkeypatch):
    drupal_root = tmp_path
    (drupal_root / "sites" / "default").mkdir(parents=True)
    (drupal_root / "sites" / "default" / "settings.php").write_text(SETTINGS_PHP)

    def fake_run_query(db_config, query):
        if "field_data_body" in query:
            return [["32", "body with EVIL() injected"]]
        if "block_custom" in query:
            return [["3", "EVIL() in a custom block"]]
        return None
    monkeypatch.setattr(wds, "run_query", fake_run_query)

    results = dds.scan_drupal_database(str(drupal_root), FakeRules())
    labels = {label for label, _rule in results}
    assert "field_data_body.body_value (entity ID 32)" in labels
    assert "block_custom.body (block ID 3)" in labels
    assert all(rule == "DangerousPhp" for _label, rule in results)


def test_scan_drupal_database_handles_missing_tables(tmp_path, monkeypatch):
    drupal_root = tmp_path
    (drupal_root / "sites" / "default").mkdir(parents=True)
    (drupal_root / "sites" / "default" / "settings.php").write_text(SETTINGS_PHP)
    monkeypatch.setattr(wds, "run_query", lambda *a, **k: None)
    assert dds.scan_drupal_database(str(drupal_root), FakeRules()) == []
