"""Unit tests for clamd_tune.py - the AppArmor profile header fix and the
"raise, never lower" clamd.conf size limits."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import clamd_tune as ct

M = 1024 ** 2


def test_fix_profile_adds_path_to_existing_flag():
    text = "#include <tunables/global>\n/usr/sbin/clamd flags=(attach_disconnected) {\n  /tmp/** r,\n}\n"
    out = ct.fix_profile(text)
    assert "/usr/sbin/clamd flags=(attach_disconnected, attach_disconnected.path=/) {" in out
    assert "/tmp/** r," in out


def test_fix_profile_no_flags_named_profile_keeps_other_flags_and_is_idempotent():
    out = ct.fix_profile("profile clamd /usr/sbin/clamd {\n}\n")
    assert out.startswith("profile clamd /usr/sbin/clamd flags=(attach_disconnected, attach_disconnected.path=/) {")
    out2 = ct.fix_profile("/usr/sbin/clamd flags=(complain) {\n}\n")
    assert "flags=(complain, attach_disconnected, attach_disconnected.path=/)" in out2
    assert ct.fix_profile(out) == out


def test_fix_clamd_conf_raises_never_lowers_and_appends_missing():
    text = "LocalSocket /run/clamav/clamd.ctl\nMaxFileSize 25M\nStreamMaxLength 500M\nMaxScanSize 0\n"
    out = ct.fix_clamd_conf(text, 200 * M)
    assert f"MaxFileSize {200 * M}\n" in out      # raised
    assert "StreamMaxLength 500M\n" in out          # admin's higher value kept
    assert "MaxScanSize 0\n" in out                 # unlimited kept
    assert ct.fix_clamd_conf(out, 200 * M) == out


def test_fix_clamd_conf_missing_directive_only_appended_above_default():
    assert ct.fix_clamd_conf("Foo bar\n", 50 * M) == "Foo bar\n"
    assert f"StreamMaxLength {150 * M}\n" in ct.fix_clamd_conf("Foo bar\n", 150 * M)
