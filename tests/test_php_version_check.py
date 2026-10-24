import sys

sys.path.insert(0, "tools")
import php_version_check as pvc


def test_patch_level_matches_branch():
    assert pvc.patch_level("8.3", "1:8.3.36-1+debian12u1") == 36


def test_patch_level_none_when_branch_does_not_match():
    assert pvc.patch_level("8.3", "1:8.4.27-1+debian12u1") is None


def test_snapshot_date_found():
    assert pvc.snapshot_date("1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428") == 20261021


def test_snapshot_date_none_when_absent():
    assert pvc.snapshot_date("1:7.4.33-1+deb11u1") is None


def test_installed_php_common_versions_parses_dpkg_output(monkeypatch):
    fake_output = (
        "php7.4-common\t1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428\n"
        "php8.3-common\t1:8.3.36-1\n"
        "apache2\t2.4.62-1\n"
    )

    class FakeResult:
        stdout = fake_output

    monkeypatch.setattr(pvc.subprocess, "run", lambda *a, **kw: FakeResult())
    found = list(pvc.installed_php_common_versions())
    assert found == [("7.4", "1:7.4.33-31+0~20261021.121+debian12~1.gbpe9c428"), ("8.3", "1:8.3.36-1")]
