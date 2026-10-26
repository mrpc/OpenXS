import gzip
import hashlib
import io
import json
import sys
import zipfile

sys.path.insert(0, "tools")
import wp_plugin_checksums as wpc


def _make_zip_bytes(slug, files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for rel, content in files.items():
            zf.writestr(f"{slug}/{rel}", content)
    return buf.getvalue()


def test_fetch_file_content_returns_the_real_bytes(monkeypatch):
    zip_bytes = _make_zip_bytes("wordfence", {"wordfence.php": "<?php // stock"})

    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return zip_bytes
    monkeypatch.setattr(wpc.urllib.request, "urlopen", lambda url, timeout=60: FakeResp())
    assert wpc.fetch_file_content("wordfence", "7.11.6", "wordfence.php") == b"<?php // stock"


def test_fetch_file_content_none_for_missing_path(monkeypatch):
    zip_bytes = _make_zip_bytes("wordfence", {"wordfence.php": "<?php // stock"})

    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return zip_bytes
    monkeypatch.setattr(wpc.urllib.request, "urlopen", lambda url, timeout=60: FakeResp())
    assert wpc.fetch_file_content("wordfence", "7.11.6", "does/not/exist.php") is None


def test_fetch_file_content_none_on_download_failure(monkeypatch):
    def fail(url, timeout=60):
        raise OSError("unreachable")
    monkeypatch.setattr(wpc.urllib.request, "urlopen", fail)
    assert wpc.fetch_file_content("wordfence", "7.11.6", "wordfence.php") is None


def test_compute_checksums_from_zip(monkeypatch):
    zip_bytes = _make_zip_bytes("wordfence", {"wordfence.php": "<?php // stock",
                                               "lib/wfConfig.php": "<?php"})

    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return zip_bytes

    monkeypatch.setattr(wpc.urllib.request, "urlopen", lambda url, timeout=30: FakeResp())
    checksums = wpc.compute_checksums_from_zip("wordfence", "7.11.6")
    assert checksums["wordfence.php"] == hashlib.sha256(b"<?php // stock").hexdigest()
    assert checksums["lib/wfConfig.php"] == hashlib.sha256(b"<?php").hexdigest()


def test_compute_checksums_from_zip_returns_none_on_download_failure(monkeypatch):
    def fail(url, timeout=30):
        raise OSError("unreachable")
    monkeypatch.setattr(wpc.urllib.request, "urlopen", fail)
    assert wpc.compute_checksums_from_zip("wordfence", "7.11.6") is None


def test_fetch_checksums_caches_to_disk(tmp_path, monkeypatch):
    monkeypatch.setattr(wpc, "CACHE_DIR", str(tmp_path))
    zip_bytes = _make_zip_bytes("loco-translate", {"loco.php": "<?php"})

    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return zip_bytes

    calls = []
    def fake_urlopen(url, timeout=30):
        calls.append(url)
        return FakeResp()
    monkeypatch.setattr(wpc.urllib.request, "urlopen", fake_urlopen)

    first = wpc.fetch_checksums("loco-translate", "2.6.5")
    second = wpc.fetch_checksums("loco-translate", "2.6.5")
    assert first == second == {"loco.php": hashlib.sha256(b"<?php").hexdigest()}
    assert len(calls) == 1  # second call used the disk cache, no re-download


def test_fetch_checksums_returns_none_for_nonexistent_plugin(tmp_path, monkeypatch):
    monkeypatch.setattr(wpc, "CACHE_DIR", str(tmp_path))
    def fail(url, timeout=30):
        raise Exception("404")
    monkeypatch.setattr(wpc.urllib.request, "urlopen", fail)
    assert wpc.fetch_checksums("not-a-real-plugin", "1.0.0") is None


def test_is_unmodified_core_file_matches(tmp_path):
    root = tmp_path
    f = root / "wordfence.php"
    f.write_bytes(b"stock content")
    checksums = {"wordfence.php": hashlib.sha256(b"stock content").hexdigest()}
    assert wpc.is_unmodified_core_file(str(f), str(root), checksums)


def test_is_unmodified_core_file_modified_content_does_not_match(tmp_path):
    root = tmp_path
    f = root / "wordfence.php"
    f.write_bytes(b"backdoored content")
    checksums = {"wordfence.php": hashlib.sha256(b"stock content").hexdigest()}
    assert not wpc.is_unmodified_core_file(str(f), str(root), checksums)
