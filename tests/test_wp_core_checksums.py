import io
import json
import sys

sys.path.insert(0, "tools")
import wp_core_checksums as wcc


def _make_wp_zip_bytes(files):
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for rel, content in files.items():
            zf.writestr(f"wordpress/{rel}", content)
    return buf.getvalue()


def test_fetch_file_content_returns_the_real_bytes(monkeypatch):
    zip_bytes = _make_wp_zip_bytes({"wp-includes/comment.php": "<?php // stock"})

    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return zip_bytes
    monkeypatch.setattr(wcc.urllib.request, "urlopen", lambda url, timeout=60: FakeResp())
    assert wcc.fetch_file_content("6.0.0", "wp-includes/comment.php") == b"<?php // stock"


def test_fetch_file_content_none_for_missing_path(monkeypatch):
    zip_bytes = _make_wp_zip_bytes({"wp-includes/comment.php": "<?php // stock"})

    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return zip_bytes
    monkeypatch.setattr(wcc.urllib.request, "urlopen", lambda url, timeout=60: FakeResp())
    assert wcc.fetch_file_content("6.0.0", "wp-includes/does-not-exist.php") is None


def test_fetch_file_content_none_on_download_failure(monkeypatch):
    def fail(url, timeout=60):
        raise OSError("unreachable")
    monkeypatch.setattr(wcc.urllib.request, "urlopen", fail)
    assert wcc.fetch_file_content("6.0.0", "wp-includes/comment.php") is None


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


# --- find_unknown_core_files -------------------------------------------------

def _write_bundle(bundled_dir, version, manifest):
    bundled_dir.mkdir(parents=True, exist_ok=True)
    import gzip
    with gzip.open(str(bundled_dir / f"{version}.json.gz"), "wt") as f:
        json.dump(manifest, f)


def test_find_unknown_core_files_ignores_known_files(tmp_path, monkeypatch):
    monkeypatch.setattr(wcc, "_all_bundled_hashes_cache", None)
    bundled_dir = tmp_path / "bundle"
    monkeypatch.setattr(wcc, "BUNDLED_DIR", str(bundled_dir))
    wp_root = tmp_path / "site"
    stock = wp_root / "wp-includes" / "comment.php"
    stock.parent.mkdir(parents=True)
    stock.write_bytes(b"stock content")
    import hashlib
    manifest = {"wp-includes/comment.php": hashlib.md5(b"stock content").hexdigest()}
    _write_bundle(bundled_dir, "6.0", manifest)
    assert wcc.find_unknown_core_files(str(wp_root), "6.0") == []


def test_find_unknown_core_files_flags_old_leftover(tmp_path, monkeypatch):
    monkeypatch.setattr(wcc, "_all_bundled_hashes_cache", None)
    bundled_dir = tmp_path / "bundle"
    monkeypatch.setattr(wcc, "BUNDLED_DIR", str(bundled_dir))
    wp_root = tmp_path / "site"
    leftover = wp_root / "wp-includes" / "old-class.php"
    leftover.parent.mkdir(parents=True)
    leftover.write_bytes(b"old release content")
    import hashlib
    old_hash = hashlib.md5(b"old release content").hexdigest()
    # Current version's manifest doesn't know this file at all, but an
    # older bundled version's manifest has its exact content hash.
    _write_bundle(bundled_dir, "6.0", {})
    _write_bundle(bundled_dir, "5.9", {"wp-includes/old-class.php": old_hash})
    results = wcc.find_unknown_core_files(str(wp_root), "6.0")
    assert results == [(str(leftover), True)]


def test_find_unknown_core_files_flags_truly_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(wcc, "_all_bundled_hashes_cache", None)
    bundled_dir = tmp_path / "bundle"
    monkeypatch.setattr(wcc, "BUNDLED_DIR", str(bundled_dir))
    wp_root = tmp_path / "site"
    planted = wp_root / "wp-admin" / "shell.php"
    planted.parent.mkdir(parents=True)
    planted.write_bytes(b"<?php system($_GET['c']); ?>")
    _write_bundle(bundled_dir, "6.0", {})
    results = wcc.find_unknown_core_files(str(wp_root), "6.0")
    assert results == [(str(planted), False)]


def test_find_unknown_core_files_ignores_error_log(tmp_path, monkeypatch):
    # Found live 2026-10-26: PHP's log_errors writes an "error_log" into
    # whatever directory the error happened in - a near-universal shared-
    # hosting default, nothing to do with WordPress or a webshell.
    monkeypatch.setattr(wcc, "_all_bundled_hashes_cache", None)
    bundled_dir = tmp_path / "bundle"
    monkeypatch.setattr(wcc, "BUNDLED_DIR", str(bundled_dir))
    wp_root = tmp_path / "site"
    log = wp_root / "wp-includes" / "error_log"
    log.parent.mkdir(parents=True)
    log.write_bytes(b"PHP Fatal error: ...")
    _write_bundle(bundled_dir, "6.0", {})
    assert wcc.find_unknown_core_files(str(wp_root), "6.0") == []


def test_find_unknown_core_files_ignores_wp_content(tmp_path, monkeypatch):
    monkeypatch.setattr(wcc, "_all_bundled_hashes_cache", None)
    bundled_dir = tmp_path / "bundle"
    monkeypatch.setattr(wcc, "BUNDLED_DIR", str(bundled_dir))
    wp_root = tmp_path / "site"
    upload = wp_root / "wp-content" / "uploads" / "whatever.php"
    upload.parent.mkdir(parents=True)
    upload.write_bytes(b"anything")
    _write_bundle(bundled_dir, "6.0", {})
    assert wcc.find_unknown_core_files(str(wp_root), "6.0") == []


def test_find_unknown_core_files_returns_empty_without_a_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(wcc, "_all_bundled_hashes_cache", None)
    monkeypatch.setattr(wcc, "BUNDLED_DIR", str(tmp_path / "no-such-bundle"))
    monkeypatch.setattr(wcc, "CACHE_DB", str(tmp_path / "cache.db"))

    def fake_urlopen(url, timeout=5):
        raise OSError("unreachable")
    monkeypatch.setattr(wcc.urllib.request, "urlopen", fake_urlopen)

    wp_root = tmp_path / "site"
    (wp_root / "wp-admin").mkdir(parents=True)
    (wp_root / "wp-admin" / "whatever.php").write_bytes(b"anything")
    assert wcc.find_unknown_core_files(str(wp_root), "99.0-unreleased") == []
