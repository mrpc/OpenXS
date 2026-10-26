import json
import sys
import time

sys.path.insert(0, "tools")
import composer_trust as ct


class FakeResp:
    def __init__(self, data):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._data


def _packagist_info(age_days, downloads):
    published = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - age_days * 86400))
    return json.dumps({"package": {"time": published, "downloads": {"total": downloads}}}).encode()


def test_whitelist_prefix_match():
    patterns = ["symfony/*", "mrpc/*", "monolog/monolog"]
    assert ct.is_whitelisted("symfony/var-exporter", patterns)
    assert ct.is_whitelisted("mrpc/beatportapi", patterns)
    assert ct.is_whitelisted("monolog/monolog", patterns)
    assert not ct.is_whitelisted("monolog/other", patterns)
    assert not ct.is_whitelisted("evil/typosquat", patterns)


def test_level_1_whitelisted_package_trusted_without_lookup(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("should not hit the network for a whitelisted package")
    monkeypatch.setattr(ct.urllib.request, "urlopen", boom)
    assert ct.is_trusted("symfony/var-exporter", paranoia_level=1) is True


def test_level_1_unknown_package_passes_low_bar(monkeypatch, tmp_path):
    monkeypatch.setattr(ct, "STATS_CACHE_DB", str(tmp_path / "stats.db"))
    monkeypatch.setattr(ct.urllib.request, "urlopen", lambda *a, **k: FakeResp(_packagist_info(200, 5000)))
    assert ct.is_trusted("some/obscure-pkg", paranoia_level=1) is True


def test_level_1_unknown_package_fails_low_bar(monkeypatch, tmp_path):
    monkeypatch.setattr(ct, "STATS_CACHE_DB", str(tmp_path / "stats.db"))
    monkeypatch.setattr(ct.urllib.request, "urlopen", lambda *a, **k: FakeResp(_packagist_info(10, 50)))
    assert ct.is_trusted("some/brand-new-pkg", paranoia_level=1) is False


def test_level_2_unknown_package_needs_much_higher_bar(monkeypatch, tmp_path):
    monkeypatch.setattr(ct, "STATS_CACHE_DB", str(tmp_path / "stats.db"))
    monkeypatch.setattr(ct.urllib.request, "urlopen", lambda *a, **k: FakeResp(_packagist_info(200, 5000)))
    assert ct.is_trusted("some/obscure-pkg", paranoia_level=2) is False
    monkeypatch.setattr(ct.urllib.request, "urlopen", lambda *a, **k: FakeResp(_packagist_info(365, 100000)))
    assert ct.is_trusted("some/well-established-pkg", paranoia_level=2) is True


def test_level_2_whitelisted_package_still_trusted(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("should not hit the network for a whitelisted package")
    monkeypatch.setattr(ct.urllib.request, "urlopen", boom)
    assert ct.is_trusted("mrpc/pramnosframework", paranoia_level=2) is True


def test_level_3_disables_trust_entirely_even_whitelisted(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("level 3 shouldn't even check the whitelist, but definitely no network")
    monkeypatch.setattr(ct.urllib.request, "urlopen", boom)
    assert ct.is_trusted("symfony/var-exporter", paranoia_level=3) is False


def test_lookup_failure_is_not_trusted(monkeypatch, tmp_path):
    monkeypatch.setattr(ct, "STATS_CACHE_DB", str(tmp_path / "stats.db"))

    def boom(*a, **k):
        raise OSError("network down")
    monkeypatch.setattr(ct.urllib.request, "urlopen", boom)
    assert ct.is_trusted("some/unreachable-pkg", paranoia_level=1) is False


def test_thresholds_are_configurable_via_env(monkeypatch, tmp_path):
    monkeypatch.setattr(ct, "STATS_CACHE_DB", str(tmp_path / "stats.db"))
    monkeypatch.setenv("OPENXS_COMPOSER_TRUST_MIN_DOWNLOADS", "100000")
    monkeypatch.setattr(ct.urllib.request, "urlopen", lambda *a, **k: FakeResp(_packagist_info(200, 5000)))
    assert ct.is_trusted("some/obscure-pkg", paranoia_level=1) is False


def test_stats_are_cached_across_calls(monkeypatch, tmp_path):
    monkeypatch.setattr(ct, "STATS_CACHE_DB", str(tmp_path / "stats.db"))
    calls = []

    def fake_urlopen(*a, **k):
        calls.append(1)
        return FakeResp(_packagist_info(200, 5000))
    monkeypatch.setattr(ct.urllib.request, "urlopen", fake_urlopen)
    assert ct.is_trusted("some/obscure-pkg", paranoia_level=1) is True
    assert ct.is_trusted("some/obscure-pkg", paranoia_level=1) is True
    assert len(calls) == 1


def test_stats_cache_survives_transient_lookup_failure(monkeypatch, tmp_path):
    import sqlite3
    monkeypatch.setattr(ct, "STATS_CACHE_DB", str(tmp_path / "stats.db"))
    monkeypatch.setattr(ct.urllib.request, "urlopen", lambda *a, **k: FakeResp(_packagist_info(200, 5000)))
    assert ct.is_trusted("some/obscure-pkg", paranoia_level=1) is True

    # Force the cache entry stale (older than STATS_CACHE_TTL) so the next
    # lookup actually attempts the network, not just reads a fresh cache.
    conn = sqlite3.connect(ct.STATS_CACHE_DB)
    conn.execute("UPDATE package_stats SET checked_at = 0")
    conn.commit()
    conn.close()

    def boom(*a, **k):
        raise OSError("transient network failure")
    monkeypatch.setattr(ct.urllib.request, "urlopen", boom)
    assert ct.is_trusted("some/obscure-pkg", paranoia_level=1) is True
