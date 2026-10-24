import gzip
import hashlib
import io
import json
import sys
import zipfile

sys.path.insert(0, "tools")
import phpmyadmin_core_checksums as pcc


def _make_zip_bytes(version, files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for rel, content in files.items():
            zf.writestr(f"phpMyAdmin-{version}-all-languages/{rel}", content)
    return buf.getvalue()


def test_compute_checksums_from_zip(monkeypatch):
    zip_bytes = _make_zip_bytes("5.2.2", {"libraries/classes/Util.php": "<?php // stock",
                                           "composer.json": '{"name": "phpmyadmin/phpmyadmin"}'})

    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return zip_bytes

    monkeypatch.setattr(pcc.urllib.request, "urlopen", lambda url, timeout=30: FakeResp())
    checksums = pcc.compute_checksums_from_zip("5.2.2")
    assert checksums["libraries/classes/Util.php"] == hashlib.sha256(b"<?php // stock").hexdigest()
    assert checksums["composer.json"] == hashlib.sha256(b'{"name": "phpmyadmin/phpmyadmin"}').hexdigest()


def test_compute_checksums_from_zip_returns_none_on_download_failure(monkeypatch):
    def fail(url, timeout=30):
        raise OSError("unreachable")
    monkeypatch.setattr(pcc.urllib.request, "urlopen", fail)
    assert pcc.compute_checksums_from_zip("5.2.2") is None


def test_bundled_checksums_used_first(tmp_path, monkeypatch):
    monkeypatch.setattr(pcc, "BUNDLED_DIR", str(tmp_path))
    with gzip.open(tmp_path / "5.2.2.json.gz", "wt") as f:
        json.dump({"libraries/classes/Util.php": "abc123"}, f)

    def should_not_be_called(*a, **kw):
        raise AssertionError("should not fetch live when bundled")
    monkeypatch.setattr(pcc, "compute_checksums_from_zip", should_not_be_called)

    assert pcc.fetch_checksums("5.2.2") == {"libraries/classes/Util.php": "abc123"}


def test_is_unmodified_core_file_matches(tmp_path):
    root = tmp_path
    f = root / "libraries" / "classes" / "Util.php"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"stock content")
    checksums = {"libraries/classes/Util.php": hashlib.sha256(b"stock content").hexdigest()}
    assert pcc.is_unmodified_core_file(str(f), str(root), checksums)


def test_is_unmodified_core_file_modified_content_does_not_match(tmp_path):
    root = tmp_path
    f = root / "libraries" / "classes" / "Util.php"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"backdoored content")
    checksums = {"libraries/classes/Util.php": hashlib.sha256(b"stock content").hexdigest()}
    assert not pcc.is_unmodified_core_file(str(f), str(root), checksums)
