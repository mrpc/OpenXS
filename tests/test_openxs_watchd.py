"""Unit tests for openxs-watchd.py's rate limiter (cxs's --Wrateignore)."""
import importlib.util
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

spec = importlib.util.spec_from_file_location(
    "openxs_watchd", os.path.join(os.path.dirname(__file__), "..", "tools", "openxs-watchd.py")
)
openxs_watchd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(openxs_watchd)


def reset():
    openxs_watchd._recent.clear()
    openxs_watchd._ignored_until.clear()


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
