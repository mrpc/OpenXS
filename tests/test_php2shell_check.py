import sys

sys.path.insert(0, "tools")
import php2shell_check as pc


def test_is_protected_true_for_official_fixed_version():
    assert pc.is_protected("8.3", "1:8.3.36-1+debian12u1")


def test_is_protected_false_for_official_version_below_fix():
    assert not pc.is_protected("8.3", "1:8.3.35-1+debian12u1")


def test_is_protected_true_for_unofficial_branch_with_post_disclosure_snapshot():
    assert pc.is_protected("7.4", "1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428")


def test_is_protected_false_for_unofficial_branch_pre_disclosure_snapshot():
    assert not pc.is_protected("7.4", "1:7.4.33-30+0~20260915.100+debian12~1.gbpabc1234")


def test_is_protected_false_for_eol_branch_with_no_snapshot_date_at_all():
    assert not pc.is_protected("7.4", "1:7.4.33-1+deb11u1")


def test_installed_php_common_versions_parses_dpkg_output(monkeypatch):
    fake_output = (
        "php7.4-common\t1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428\n"
        "php8.3-common\t1:8.3.36-1\n"
        "apache2\t2.4.62-1\n"
    )

    class FakeResult:
        stdout = fake_output

    monkeypatch.setattr(pc.subprocess, "run", lambda *a, **kw: FakeResult())
    found = list(pc.installed_php_common_versions())
    assert found == [("7.4", "1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428"), ("8.3", "1:8.3.36-1")]


def test_main_exits_zero_when_all_protected(monkeypatch, capsys):
    monkeypatch.setattr(pc, "installed_php_common_versions",
                         lambda: [("8.3", "1:8.3.36-1")])
    with __import__("pytest").raises(SystemExit) as exc_info:
        pc.main()
    assert exc_info.value.code == 0


def test_main_exits_one_when_any_unprotected(monkeypatch):
    monkeypatch.setattr(pc, "installed_php_common_versions",
                         lambda: [("8.3", "1:8.3.36-1"), ("7.4", "1:7.4.33-1+deb11u1")])
    with __import__("pytest").raises(SystemExit) as exc_info:
        pc.main()
    assert exc_info.value.code == 1
