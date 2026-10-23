"""Unit tests for check_whitelist_drift.py."""
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import check_whitelist_drift as cwd


def make_whitelist(tmp_path, entries):
    """entries: list of (path, content) - writes the file and a matching
    whitelist.yar pointing at its current hash."""
    lines = ['import "hash"\n\nprivate rule Custom\n{\n    condition:']
    for path, content in entries:
        path.write_text(content)
        h = hashlib.sha1(content.encode()).hexdigest()
        lines.append(f'        hash.sha1(0, filesize) == "{h}" or // {path}')
    lines.append("        false\n}")
    wl = tmp_path / "custom.yar"
    wl.write_text("\n".join(lines))
    return wl


def test_unchanged_files_report_clean(tmp_path):
    f = tmp_path / "a.php"
    wl = make_whitelist(tmp_path, [(f, "<?php echo 1; ?>")])
    checked, changed, missing = cwd.check(str(wl))
    assert checked == 1
    assert changed == []
    assert missing == []


def test_changed_file_is_detected(tmp_path):
    f = tmp_path / "a.php"
    wl = make_whitelist(tmp_path, [(f, "<?php echo 1; ?>")])
    f.write_text("<?php echo 2; ?>")  # content changed after whitelisting
    checked, changed, missing = cwd.check(str(wl))
    assert changed == [str(f)]
    assert missing == []


def test_deleted_file_is_reported_missing(tmp_path):
    f = tmp_path / "a.php"
    wl = make_whitelist(tmp_path, [(f, "<?php echo 1; ?>")])
    f.unlink()
    checked, changed, missing = cwd.check(str(wl))
    assert changed == []
    assert missing == [str(f)]


def test_ignores_entries_outside_the_custom_rule(tmp_path):
    # php-malware-finder's own built-in whitelists (Magento, Roundcube, ...)
    # live in differently-named rules and should never be drift-checked -
    # their paths are relative to generic third-party apps, not this host.
    f = tmp_path / "a.php"
    f.write_text("<?php ?>")
    wl = tmp_path / "whitelist.yar"
    wl.write_text(
        'import "hash"\n\n'
        "private rule Magento : ECommerce\n{\n    condition:\n"
        '        hash.sha1(0, filesize) == "0000000000000000000000000000000000000000" or // lib/PEAR/XML/Parser.php\n'
        "        false\n}\n\n"
        "private rule Custom\n{\n    condition:\n"
        f'        hash.sha1(0, filesize) == "{hashlib.sha1(b"<?php ?>").hexdigest()}" or // {f}\n'
        "        false\n}\n"
    )
    checked, changed, missing = cwd.check(str(wl))
    assert checked == 1  # only the Custom-rule entry, not the Magento one
    assert changed == []
    assert missing == []


def test_multiple_entries_only_flags_the_changed_one(tmp_path):
    f1 = tmp_path / "a.php"
    f2 = tmp_path / "b.php"
    wl = make_whitelist(tmp_path, [(f1, "<?php echo 1; ?>"), (f2, "<?php echo 2; ?>")])
    f2.write_text("<?php echo 999; ?>")
    checked, changed, missing = cwd.check(str(wl))
    assert checked == 2
    assert changed == [str(f2)]
    assert missing == []
