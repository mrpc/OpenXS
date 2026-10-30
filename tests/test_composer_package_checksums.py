import hashlib
import io
import json
import sys
import zipfile

sys.path.insert(0, "tools")
import composer_package_checksums as cpc


class FakeResp:
    def __init__(self, data):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._data


def _make_zip_bytes(top_dir, files):
    # GitHub codeload zips name their one top-level dir
    # "<owner>-<repo>-<short-sha>/" - never the package/version string
    # itself, which is exactly why the real code can't assume it.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for rel, content in files.items():
            zf.writestr(f"{top_dir}/{rel}", content)
    return buf.getvalue()


def _packagist_response(name, version, dist_url):
    return json.dumps({
        "packages": {name: [{"version": version, "dist": {"url": dist_url}}]}
    }).encode()


def test_compute_checksums_from_zip(monkeypatch):
    dist_url = "https://api.github.com/repos/symfony/var-exporter/zipball/abc123"
    zip_bytes = _make_zip_bytes("symfony-var-exporter-abc123",
                                {"Hydrator.php": "<?php // stock", "Exception/LogicException.php": "<?php"})

    def fake_urlopen(req, timeout=30):
        url = req if isinstance(req, str) else req.full_url
        if "repo.packagist.org" in url:
            return FakeResp(_packagist_response("symfony/var-exporter", "v8.1.9", dist_url))
        return FakeResp(zip_bytes)

    monkeypatch.setattr(cpc.urllib.request, "urlopen", fake_urlopen)
    checksums = cpc.compute_checksums_from_zip("symfony/var-exporter", "v8.1.9")
    assert checksums["Hydrator.php"] == hashlib.sha256(b"<?php // stock").hexdigest()
    assert checksums["Exception/LogicException.php"] == hashlib.sha256(b"<?php").hexdigest()


def test_compute_checksums_from_zip_returns_none_when_version_not_on_packagist(monkeypatch):
    def fake_urlopen(req, timeout=30):
        return FakeResp(_packagist_response("symfony/var-exporter", "v8.1.9", "https://example/dist.zip"))
    monkeypatch.setattr(cpc.urllib.request, "urlopen", fake_urlopen)
    # Asking for a DIFFERENT version than the one the fake metadata has.
    assert cpc.compute_checksums_from_zip("symfony/var-exporter", "v1.0.0") is None


def test_compute_checksums_from_zip_returns_none_on_download_failure(monkeypatch):
    def fail(req, timeout=30):
        raise OSError("unreachable")
    monkeypatch.setattr(cpc.urllib.request, "urlopen", fail)
    assert cpc.compute_checksums_from_zip("symfony/var-exporter", "v8.1.9") is None


def test_fetch_file_content_returns_the_real_bytes(monkeypatch):
    dist_url = "https://api.github.com/repos/symfony/var-exporter/zipball/abc123"
    zip_bytes = _make_zip_bytes("symfony-var-exporter-abc123", {"Hydrator.php": "<?php // stock"})
    monkeypatch.setattr(cpc.urllib.request, "urlopen", lambda req, timeout=30: FakeResp(zip_bytes))
    content = cpc.fetch_file_content("symfony/var-exporter", "v7.4.18", "Hydrator.php", dist_url=dist_url)
    assert content == b"<?php // stock"


def test_fetch_file_content_none_for_missing_path(monkeypatch):
    dist_url = "https://api.github.com/repos/symfony/var-exporter/zipball/abc123"
    zip_bytes = _make_zip_bytes("symfony-var-exporter-abc123", {"Hydrator.php": "<?php // stock"})
    monkeypatch.setattr(cpc.urllib.request, "urlopen", lambda req, timeout=30: FakeResp(zip_bytes))
    content = cpc.fetch_file_content("symfony/var-exporter", "v7.4.18", "does/not/exist.php", dist_url=dist_url)
    assert content is None


def test_fetch_file_content_none_when_dist_url_unresolvable(monkeypatch):
    monkeypatch.setattr(cpc, "_find_dist_url", lambda name, version, timeout=10: None)
    content = cpc.fetch_file_content("acme/private-package", "1.0.0", "x.php")
    assert content is None


def test_is_github_api_host_rejects_substring_spoofing():
    # dist_url is untrusted (from Packagist's API, or composer.lock) -
    # a plain "api.github.com" in url substring check would also match
    # these, leaking GITHUB_TOKEN to a host we don't control.
    assert cpc._is_github_api_host("https://api.github.com/repos/acme/thing/zipball/x") is True
    assert cpc._is_github_api_host("https://api.github.com.evil.example/x") is False
    assert cpc._is_github_api_host("https://evil.example/?x=api.github.com") is False
    assert cpc._is_github_api_host("not a url at all") is False


def test_fetch_checksums_caches_to_disk(tmp_path, monkeypatch):
    monkeypatch.setattr(cpc, "CACHE_DIR", str(tmp_path))
    dist_url = "https://api.github.com/repos/acme/thing/zipball/def456"
    zip_bytes = _make_zip_bytes("acme-thing-def456", {"Thing.php": "<?php"})

    calls = []
    def fake_urlopen(req, timeout=30):
        url = req if isinstance(req, str) else req.full_url
        calls.append(url)
        if "repo.packagist.org" in url:
            return FakeResp(_packagist_response("acme/thing", "1.2.3", dist_url))
        return FakeResp(zip_bytes)
    monkeypatch.setattr(cpc.urllib.request, "urlopen", fake_urlopen)

    first = cpc.fetch_checksums("acme/thing", "1.2.3")
    second = cpc.fetch_checksums("acme/thing", "1.2.3")
    assert first == second == {"Thing.php": hashlib.sha256(b"<?php").hexdigest()}
    assert len(calls) == 2  # one packagist + one dist call on the FIRST fetch only


def test_fetch_checksums_returns_none_for_private_package(tmp_path, monkeypatch):
    monkeypatch.setattr(cpc, "CACHE_DIR", str(tmp_path))
    def fail(req, timeout=10):
        raise Exception("404")
    monkeypatch.setattr(cpc.urllib.request, "urlopen", fail)
    assert cpc.fetch_checksums("acme/not-on-packagist", "1.0.0") is None


def test_is_unmodified_core_file_matches(tmp_path):
    root = tmp_path
    f = root / "Hydrator.php"
    f.write_bytes(b"stock content")
    checksums = {"Hydrator.php": hashlib.sha256(b"stock content").hexdigest()}
    assert cpc.is_unmodified_core_file(str(f), str(root), checksums)


def test_is_unmodified_core_file_modified_content_does_not_match(tmp_path):
    root = tmp_path
    f = root / "Hydrator.php"
    f.write_bytes(b"backdoored content")
    checksums = {"Hydrator.php": hashlib.sha256(b"stock content").hexdigest()}
    assert not cpc.is_unmodified_core_file(str(f), str(root), checksums)
