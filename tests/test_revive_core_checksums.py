import gzip
import hashlib
import io
import json
import sys
import tarfile

sys.path.insert(0, "tools")
import revive_core_checksums as rcc


def _make_tarball_bytes(version, files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"revive-adserver-{version}/{rel}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_compute_checksums_from_tarball(monkeypatch):
    tarball_bytes = _make_tarball_bytes("6.0.8", {"www/delivery/cl.php": "<?php // stock", "constants.php": "<?php"})

    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return tarball_bytes

    monkeypatch.setattr(rcc.urllib.request, "urlopen", lambda url, timeout=30: FakeResp())
    checksums = rcc.compute_checksums_from_tarball("6.0.8")
    assert checksums["www/delivery/cl.php"] == hashlib.sha256(b"<?php // stock").hexdigest()
    assert checksums["constants.php"] == hashlib.sha256(b"<?php").hexdigest()


def test_compute_checksums_from_tarball_returns_none_on_download_failure(monkeypatch):
    def fail(url, timeout=30):
        raise OSError("unreachable")
    monkeypatch.setattr(rcc.urllib.request, "urlopen", fail)
    assert rcc.compute_checksums_from_tarball("6.0.8") is None


def test_bundled_checksums_used_first(tmp_path, monkeypatch):
    monkeypatch.setattr(rcc, "BUNDLED_DIR", str(tmp_path))
    with gzip.open(tmp_path / "6.0.8.json.gz", "wt") as f:
        json.dump({"constants.php": "abc123"}, f)

    def should_not_be_called(*a, **kw):
        raise AssertionError("should not fetch live when bundled")
    monkeypatch.setattr(rcc, "compute_checksums_from_tarball", should_not_be_called)

    assert rcc.fetch_checksums("6.0.8") == {"constants.php": "abc123"}


def test_is_unmodified_core_file_matches(tmp_path):
    revive_root = tmp_path
    f = revive_root / "www" / "delivery" / "cl.php"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"stock content")
    checksums = {"www/delivery/cl.php": hashlib.sha256(b"stock content").hexdigest()}
    assert rcc.is_unmodified_core_file(str(f), str(revive_root), checksums)


def test_is_unmodified_core_file_modified_content_does_not_match(tmp_path):
    revive_root = tmp_path
    f = revive_root / "www" / "delivery" / "cl.php"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"backdoored content")
    checksums = {"www/delivery/cl.php": hashlib.sha256(b"stock content").hexdigest()}
    assert not rcc.is_unmodified_core_file(str(f), str(revive_root), checksums)
