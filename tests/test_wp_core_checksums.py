import json
import sys

sys.path.insert(0, "tools")
import wp_core_checksums as wcc


def test_fetch_checksums_caches_across_calls(tmp_path, monkeypatch):
    db = tmp_path / "cache.db"
    monkeypatch.setattr(wcc, "CACHE_DB", str(db))

    calls = []

    def fake_urlopen(url, timeout=5):
        calls.append(url)
        class R:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def read(self):
                return json.dumps({"checksums": {"wp-includes/foo.php": "abc123"}}).encode()
        return R()

    monkeypatch.setattr(wcc.urllib.request, "urlopen", fake_urlopen)

    first = wcc.fetch_checksums("6.0.0")
    second = wcc.fetch_checksums("6.0.0")
    assert first == {"wp-includes/foo.php": "abc123"}
    assert second == first
    assert len(calls) == 1  # second call was served from cache, no new request


def test_fetch_checksums_returns_none_when_unreachable(tmp_path, monkeypatch):
    monkeypatch.setattr(wcc, "CACHE_DB", str(tmp_path / "cache.db"))

    def fake_urlopen(url, timeout=5):
        raise OSError("unreachable")

    monkeypatch.setattr(wcc.urllib.request, "urlopen", fake_urlopen)
    assert wcc.fetch_checksums("6.0.0") is None


def test_file_md5(tmp_path):
    f = tmp_path / "x.txt"
    f.write_bytes(b"hello world")
    import hashlib
    assert wcc.file_md5(str(f)) == hashlib.md5(b"hello world").hexdigest()


def test_file_md5_missing_file():
    assert wcc.file_md5("/no/such/file") is None


def test_is_unmodified_core_file_matches(tmp_path):
    wp_root = tmp_path
    f = wp_root / "wp-includes" / "comment.php"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"stock content")
    import hashlib
    checksums = {"wp-includes/comment.php": hashlib.md5(b"stock content").hexdigest()}
    assert wcc.is_unmodified_core_file(str(f), str(wp_root), checksums)


def test_is_unmodified_core_file_modified_content_does_not_match(tmp_path):
    wp_root = tmp_path
    f = wp_root / "wp-includes" / "comment.php"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"backdoored content")
    import hashlib
    checksums = {"wp-includes/comment.php": hashlib.md5(b"stock content").hexdigest()}
    assert not wcc.is_unmodified_core_file(str(f), str(wp_root), checksums)


def test_is_unmodified_core_file_unknown_path(tmp_path):
    wp_root = tmp_path
    f = wp_root / "wp-content" / "plugins" / "whatever.php"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"anything")
    assert not wcc.is_unmodified_core_file(str(f), str(wp_root), {})
