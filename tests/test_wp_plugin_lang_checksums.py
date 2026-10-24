import gzip
import hashlib
import io
import json
import sys
import zipfile

sys.path.insert(0, "tools")
import wp_plugin_lang_checksums as wplc


def _make_translation_zip_bytes(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)  # flat, no directory prefix
    return buf.getvalue()


def test_compute_checksums_from_zip(monkeypatch):
    zip_bytes = _make_translation_zip_bytes({
        "jetpack-el.l10n.php": "<?php // stock translations",
        "jetpack-el.mo": "binary-ish",
    })

    monkeypatch.setattr(wplc, "_package_url", lambda slug, version, locale, timeout=15: "https://example/el.zip")

    class FakeResp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return zip_bytes

    monkeypatch.setattr(wplc.urllib.request, "urlopen", lambda url, timeout=30: FakeResp())
    checksums = wplc.compute_checksums_from_zip("jetpack", "16.3.1", "el")
    assert checksums["jetpack-el.l10n.php"] == hashlib.sha256(b"<?php // stock translations").hexdigest()


def test_compute_checksums_from_zip_returns_none_when_no_package_url(monkeypatch):
    monkeypatch.setattr(wplc, "_package_url", lambda slug, version, locale, timeout=15: None)
    assert wplc.compute_checksums_from_zip("jetpack", "16.3.1", "xx") is None


def test_fetch_checksums_caches_to_disk(tmp_path, monkeypatch):
    monkeypatch.setattr(wplc, "CACHE_DIR", str(tmp_path))
    zip_bytes = _make_translation_zip_bytes({"loco-translate-el.l10n.php": "<?php"})
    monkeypatch.setattr(wplc, "_package_url", lambda slug, version, locale, timeout=15: "https://example/el.zip")

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
    monkeypatch.setattr(wplc.urllib.request, "urlopen", fake_urlopen)

    first = wplc.fetch_checksums("loco-translate", "2.6.5", "el")
    second = wplc.fetch_checksums("loco-translate", "2.6.5", "el")
    assert first == second
    assert len(calls) == 1


def test_is_unmodified_core_file_matches_by_basename(tmp_path):
    f = tmp_path / "jetpack-el.l10n.php"
    f.write_bytes(b"stock content")
    checksums = {"jetpack-el.l10n.php": hashlib.sha256(b"stock content").hexdigest()}
    assert wplc.is_unmodified_core_file(str(f), checksums)


def test_is_unmodified_core_file_modified_content_does_not_match(tmp_path):
    f = tmp_path / "jetpack-el.l10n.php"
    f.write_bytes(b"backdoored content")
    checksums = {"jetpack-el.l10n.php": hashlib.sha256(b"stock content").hexdigest()}
    assert not wplc.is_unmodified_core_file(str(f), checksums)
