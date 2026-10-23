"""Unit tests for openxs-watchd.py's rate limiter (cxs's --Wrateignore)."""
import importlib.util
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

spec = importlib.util.spec_from_file_location(
    "openxs_watchd", os.path.join(os.path.dirname(__file__), "..", "tools", "openxs-watchd.py")
)
openxs_watchd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(openxs_watchd)


def reset():
    openxs_watchd._recent.clear()
    openxs_watchd._ignored_until.clear()
    openxs_watchd._last_sweep_ts = 0.0


def test_allows_events_under_the_count_threshold():
    reset()
    for _ in range(5):
        assert not openxs_watchd.rate_limited("/a.log", count=5, window=10, cooldown=60)


def test_rate_limits_after_exceeding_count():
    reset()
    for _ in range(5):
        openxs_watchd.rate_limited("/a.log", count=5, window=10, cooldown=60)
    # the 6th event within the window exceeds count=5
    assert openxs_watchd.rate_limited("/a.log", count=5, window=10, cooldown=60)


def test_different_files_are_tracked_independently():
    reset()
    for _ in range(5):
        openxs_watchd.rate_limited("/a.log", count=5, window=10, cooldown=60)
    openxs_watchd.rate_limited("/a.log", count=5, window=10, cooldown=60)  # trips /a.log into cooldown
    assert not openxs_watchd.rate_limited("/b.log", count=5, window=10, cooldown=60)


def test_cooldown_expires_and_resets_the_window(monkeypatch):
    reset()
    base = 1000.0
    monkeypatch.setattr(time, "time", lambda: base)
    for _ in range(6):
        openxs_watchd.rate_limited("/a.log", count=5, window=10, cooldown=1)
    assert openxs_watchd.rate_limited("/a.log", count=5, window=10, cooldown=1)  # still in cooldown

    monkeypatch.setattr(time, "time", lambda: base + 2)  # cooldown (1s) has passed
    assert not openxs_watchd.rate_limited("/a.log", count=5, window=10, cooldown=1)


def test_old_events_outside_window_dont_count(monkeypatch):
    reset()
    base = 1000.0
    monkeypatch.setattr(time, "time", lambda: base)
    for _ in range(5):
        openxs_watchd.rate_limited("/a.log", count=5, window=10, cooldown=60)

    monkeypatch.setattr(time, "time", lambda: base + 20)  # well past the 10s window
    assert not openxs_watchd.rate_limited("/a.log", count=5, window=10, cooldown=60)


def test_stale_entries_are_swept_so_one_off_files_dont_leak_forever(monkeypatch):
    # The real bug found on balrog: thousands of distinct one-off files
    # (touched once, never again) each left their own permanent entry in
    # _recent - this never got cleaned up on its own, since only a file
    # that actually gets rate-limited is ever popped.
    reset()
    base = 1000.0
    monkeypatch.setattr(time, "time", lambda: base)
    for i in range(50):
        openxs_watchd.rate_limited(f"/one-off-{i}.tmp", count=5, window=10, cooldown=60)
    assert len(openxs_watchd._recent) == 50

    # Window has long since passed for all of them, and a later event
    # (for an unrelated file) triggers the periodic sweep.
    monkeypatch.setattr(time, "time", lambda: base + 100)
    openxs_watchd.rate_limited("/unrelated.log", count=5, window=10, cooldown=60)
    assert len(openxs_watchd._recent) == 1  # only /unrelated.log remains


def test_check_rss_guard_exits_when_over_limit(monkeypatch):
    monkeypatch.setattr(openxs_watchd.pmf_scan, "vmrss_kb", lambda: 2_000_000)
    with pytest.raises(SystemExit) as exc:
        openxs_watchd.check_rss_guard(max_rss_kb=1_000_000)
    assert exc.value.code == 1


def test_check_rss_guard_does_nothing_under_limit(monkeypatch):
    monkeypatch.setattr(openxs_watchd.pmf_scan, "vmrss_kb", lambda: 500_000)
    openxs_watchd.check_rss_guard(max_rss_kb=1_000_000)  # must not raise


def test_check_rss_guard_disabled_when_limit_is_zero(monkeypatch):
    monkeypatch.setattr(openxs_watchd.pmf_scan, "vmrss_kb", lambda: 99_999_999)
    openxs_watchd.check_rss_guard(max_rss_kb=0)  # must not raise
