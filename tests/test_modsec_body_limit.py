"""Unit tests for modsec_body_limit.py - deriving ModSecurity's body-size
caps from this server's own actual PHP configuration (global php.ini AND
per-FPM-pool overrides) instead of a fixed number."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import modsec_body_limit as mbl


def test_parse_php_size_megabytes():
    assert mbl.parse_php_size("128M") == 128 * 1024 ** 2


def test_parse_php_size_gigabytes():
    assert mbl.parse_php_size("2G") == 2 * 1024 ** 3


def test_parse_php_size_bare_bytes():
    assert mbl.parse_php_size("100000") == 100000


def test_parse_php_size_unparseable_returns_none():
    assert mbl.parse_php_size("unlimited") is None


def test_max_directive_value_reads_php_ini(tmp_path):
    ini = tmp_path / "php.ini"
    ini.write_text("upload_max_filesize = 64M\npost_max_size = 128M\n")
    assert mbl._max_directive_value(str(ini), "upload_max_filesize") == 64 * 1024 ** 2
    assert mbl._max_directive_value(str(ini), "post_max_size") == 128 * 1024 ** 2


def test_max_directive_value_zero_means_unlimited_and_is_skipped(tmp_path):
    ini = tmp_path / "php.ini"
    ini.write_text("post_max_size = 0\n")
    assert mbl._max_directive_value(str(ini), "post_max_size") is None


def test_max_pool_override_value_reads_fpm_pool_conf(tmp_path):
    # Found live on prodserver (2026-10-26): a real site's pool overrides its
    # PHP version's own php.ini default by a huge margin (2048M here).
    pool = tmp_path / "12345.conf"
    pool.write_text(
        "[12345]\n"
        "php_admin_value[post_max_size] = 2048M\n"
        "php_admin_value[upload_max_filesize] = 2048M\n"
    )
    assert mbl._max_pool_override_value(str(pool)) == 2048 * 1024 ** 2


def test_max_pool_override_value_handles_php_value_variant(tmp_path):
    pool = tmp_path / "12345.conf"
    pool.write_text("php_value[upload_max_filesize] = 32M\n")
    assert mbl._max_pool_override_value(str(pool)) == 32 * 1024 ** 2


def test_max_pool_override_value_none_when_no_override(tmp_path):
    pool = tmp_path / "12345.conf"
    pool.write_text("listen = /run/php/12345.sock\n")
    assert mbl._max_pool_override_value(str(pool)) is None


def test_max_configured_php_body_bytes_combines_ini_and_pool_overrides(tmp_path, monkeypatch):
    ini_dir = tmp_path / "ini"
    ini_dir.mkdir()
    ini = ini_dir / "php.ini"
    ini.write_text("upload_max_filesize = 64M\npost_max_size = 64M\n")

    pool_dir = tmp_path / "pools"
    pool_dir.mkdir()
    pool_low = pool_dir / "low.conf"
    pool_low.write_text("php_admin_value[upload_max_filesize] = 16M\n")
    pool_high = pool_dir / "high.conf"
    pool_high.write_text("php_admin_value[upload_max_filesize] = 2048M\n")

    monkeypatch.setattr(mbl, "find_php_ini_files", lambda: [str(ini)])
    monkeypatch.setattr(mbl, "find_pool_conf_files", lambda: [str(pool_low), str(pool_high)])

    # The one pool with the much larger override must win over both the
    # global php.ini default AND the other, lower-overriding pool.
    assert mbl.max_configured_php_body_bytes() == 2048 * 1024 ** 2


def test_recommended_limits_falls_back_to_modsec_defaults_when_nothing_found(monkeypatch):
    monkeypatch.setattr(mbl, "find_php_ini_files", lambda: [])
    monkeypatch.setattr(mbl, "find_pool_conf_files", lambda: [])
    body_limit, no_files_limit = mbl.recommended_limits()
    assert body_limit == mbl.MODSEC_DEFAULT_REQUEST_BODY_LIMIT
    assert no_files_limit == mbl.MODSEC_DEFAULT_REQUEST_BODY_NO_FILES_LIMIT


def test_recommended_limits_adds_margin_above_the_detected_php_max(monkeypatch):
    monkeypatch.setattr(mbl, "max_configured_php_body_bytes", lambda: 500 * 1024 ** 2)
    body_limit, no_files_limit = mbl.recommended_limits()
    expected = 500 * 1024 ** 2 + mbl.MULTIPART_OVERHEAD_MARGIN
    assert body_limit == expected
    assert no_files_limit == expected
