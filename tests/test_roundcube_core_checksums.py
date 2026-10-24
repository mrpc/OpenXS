import gzip
import hashlib
import io
import json
import sys
import tarfile

sys.path.insert(0, "tools")
import roundcube_core_checksums as rcc


def _make_tarball_bytes(version, files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"roundcubemail-{version}/{rel}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_compute_checksums_from_tarball(monkeypatch):
    tarball_bytes = _make_tarball_bytes("1.6.9", {"program/lib/Roundcube/rcube.php": "<?php // stock",
                                                   "program/include/iniset.php": "<?php"})

    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return tarball_bytes

    monkeypatch.setattr(rcc.urllib.request, "urlopen", lambda url, timeout=30: FakeResp())
    checksums = rcc.compute_checksums_from_tarball("1.6.9")
    assert checksums["program/lib/Roundcube/rcube.php"] == hashlib.sha256(b"<?php // stock").hexdigest()
    assert checksums["program/include/iniset.php"] == hashlib.sha256(b"<?php").hexdigest()


def test_compute_checksums_from_tarball_returns_none_on_download_failure(monkeypatch):
    def fail(url, timeout=30):
        raise OSError("unreachable")
    monkeypatch.setattr(rcc.urllib.request, "urlopen", fail)
    assert rcc.compute_checksums_from_tarball("1.6.9") is None


def test_bundled_checksums_used_first(tmp_path, monkeypatch):
    monkeypatch.setattr(rcc, "BUNDLED_DIR", str(tmp_path))
    with gzip.open(tmp_path / "1.6.9.json.gz", "wt") as f:
        json.dump({"program/include/iniset.php": "abc123"}, f)

    def should_not_be_called(*a, **kw):
        raise AssertionError("should not fetch live when bundled")
    monkeypatch.setattr(rcc, "compute_checksums_from_tarball", should_not_be_called)

    assert rcc.fetch_checksums("1.6.9") == {"program/include/iniset.php": "abc123"}


def test_is_unmodified_core_file_matches(tmp_path):
    root = tmp_path
    f = root / "program" / "include" / "iniset.php"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"stock content")
    checksums = {"program/include/iniset.php": hashlib.sha256(b"stock content").hexdigest()}
    assert rcc.is_unmodified_core_file(str(f), str(root), checksums)


def test_is_unmodified_core_file_modified_content_does_not_match(tmp_path):
    root = tmp_path
    f = root / "program" / "include" / "iniset.php"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"backdoored content")
    checksums = {"program/include/iniset.php": hashlib.sha256(b"stock content").hexdigest()}
    assert not rcc.is_unmodified_core_file(str(f), str(root), checksums)
