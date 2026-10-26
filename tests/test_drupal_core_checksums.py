import gzip
import hashlib
import io
import json
import sys
import tarfile

sys.path.insert(0, "tools")
import drupal_core_checksums as dcc


def _make_tarball_bytes(version, files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"drupal-{version}/{rel}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_compute_checksums_from_tarball(monkeypatch):
    tarball_bytes = _make_tarball_bytes("7.32", {"index.php": "<?php // stock", "includes/bootstrap.inc": "<?php"})

    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return tarball_bytes

    monkeypatch.setattr(dcc.urllib.request, "urlopen", lambda url, timeout=30: FakeResp())
    checksums = dcc.compute_checksums_from_tarball("7.32")
    assert checksums["index.php"] == hashlib.sha256(b"<?php // stock").hexdigest()
    assert checksums["includes/bootstrap.inc"] == hashlib.sha256(b"<?php").hexdigest()


def test_compute_checksums_from_tarball_returns_none_on_download_failure(monkeypatch):
    def fail(url, timeout=30):
        raise OSError("unreachable")
    monkeypatch.setattr(dcc.urllib.request, "urlopen", fail)
    assert dcc.compute_checksums_from_tarball("7.32") is None


def test_fetch_file_content_returns_the_real_bytes(monkeypatch):
    tarball_bytes = _make_tarball_bytes("7.32", {"index.php": "<?php // stock"})

    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return tarball_bytes

    monkeypatch.setattr(dcc.urllib.request, "urlopen", lambda url, timeout=30: FakeResp())
    assert dcc.fetch_file_content("7.32", "index.php") == b"<?php // stock"


def test_fetch_file_content_none_for_missing_path(monkeypatch):
    tarball_bytes = _make_tarball_bytes("7.32", {"index.php": "<?php // stock"})

    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return tarball_bytes

    monkeypatch.setattr(dcc.urllib.request, "urlopen", lambda url, timeout=30: FakeResp())
    assert dcc.fetch_file_content("7.32", "does/not/exist.php") is None


def test_fetch_file_content_none_on_download_failure(monkeypatch):
    def fail(url, timeout=30):
        raise OSError("unreachable")
    monkeypatch.setattr(dcc.urllib.request, "urlopen", fail)
    assert dcc.fetch_file_content("7.32", "index.php") is None


def test_bundled_checksums_used_first(tmp_path, monkeypatch):
    monkeypatch.setattr(dcc, "BUNDLED_DIR", str(tmp_path))
    with gzip.open(tmp_path / "7.32.json.gz", "wt") as f:
        json.dump({"index.php": "abc123"}, f)

    def should_not_be_called(*a, **kw):
        raise AssertionError("should not fetch live when bundled")
    monkeypatch.setattr(dcc, "compute_checksums_from_tarball", should_not_be_called)

    assert dcc.fetch_checksums("7.32") == {"index.php": "abc123"}


def test_is_unmodified_core_file_matches(tmp_path):
    drupal_root = tmp_path
    f = drupal_root / "includes" / "bootstrap.inc"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"stock content")
    checksums = {"includes/bootstrap.inc": hashlib.sha256(b"stock content").hexdigest()}
    assert dcc.is_unmodified_core_file(str(f), str(drupal_root), checksums)


def test_is_unmodified_core_file_modified_content_does_not_match(tmp_path):
    drupal_root = tmp_path
    f = drupal_root / "includes" / "bootstrap.inc"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"backdoored content")
    checksums = {"includes/bootstrap.inc": hashlib.sha256(b"stock content").hexdigest()}
    assert not dcc.is_unmodified_core_file(str(f), str(drupal_root), checksums)
