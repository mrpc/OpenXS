import os
import sys

sys.path.insert(0, "tools")
import wp_upgrade_rce_check as wc


def test_scan_roots_accounts_mode():
    conf = {"SCAN_MODE": "accounts", "ACCOUNTS_DIR": "/home", "ACCOUNTS_SUBPATH": "public_html",
            "SCAN_PATH": "/var/www"}
    roots = wc.scan_roots(conf)
    assert all(r.startswith("/home/") and r.endswith("/public_html") for r in roots) or roots == []


def test_scan_roots_plain_mode():
    conf = {"SCAN_MODE": "", "ACCOUNTS_DIR": "/home", "ACCOUNTS_SUBPATH": "", "SCAN_PATH": "/var/www"}
    assert wc.scan_roots(conf) == ["/var/www"]


def test_any_wordpress_installed_true(tmp_path, monkeypatch):
    wp_includes = tmp_path / "site" / "wp-includes"
    wp_includes.mkdir(parents=True)
    (wp_includes / "version.php").write_text("<?php\n$wp_version = '6.8.1';\n")
    conf = {"SCAN_MODE": "", "ACCOUNTS_DIR": "/home", "ACCOUNTS_SUBPATH": "", "SCAN_PATH": str(tmp_path)}
    assert wc.any_wordpress_installed(conf) is True


def test_any_wordpress_installed_false(tmp_path):
    conf = {"SCAN_MODE": "", "ACCOUNTS_DIR": "/home", "ACCOUNTS_SUBPATH": "", "SCAN_PATH": str(tmp_path)}
    assert wc.any_wordpress_installed(conf) is False


def test_main_exits_one_when_wordpress_found(monkeypatch):
    monkeypatch.setattr(wc, "any_wordpress_installed", lambda conf: True)
    with __import__("pytest").raises(SystemExit) as exc_info:
        wc.main()
    assert exc_info.value.code == 1


def test_main_exits_zero_when_no_wordpress(monkeypatch):
    monkeypatch.setattr(wc, "any_wordpress_installed", lambda conf: False)
    with __import__("pytest").raises(SystemExit) as exc_info:
        wc.main()
    assert exc_info.value.code == 0


def test_rule_normalizes_path_before_matching():
    # Without these, /wp-content/./upgrade/x.php, /wp-content//upgrade/x.php
    # and /wp-content/%75pgrade/x.php slip past the rule while Apache still
    # maps them to the same file and runs it (verified on mod_security2 2.9.11).
    with open(os.path.join("tools", "modsec-rules", "wp-upgrade-rce.conf")) as f:
        conf = f.read()
    assert "t:none,t:urlDecodeUni,t:normalizePath" in conf
