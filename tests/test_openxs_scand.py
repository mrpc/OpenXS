"""Unit tests for openxs-scand.py's config-reading helper (not the socket
server itself - that needs a running process, not a unit test)."""
import importlib.util
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

spec = importlib.util.spec_from_file_location(
    "openxs_scand", os.path.join(os.path.dirname(__file__), "..", "tools", "openxs-scand.py")
)
openxs_scand = importlib.util.module_from_spec(spec)
spec.loader.exec_module(openxs_scand)


def test_load_paranoia_level_defaults_to_1_without_config(monkeypatch):
    monkeypatch.setattr(openxs_scand, "CONFIG", "/no/such/file")
    assert openxs_scand.load_paranoia_level() == 1


def test_load_paranoia_level_reads_config(tmp_path, monkeypatch):
    config = tmp_path / "openxs.conf"
    config.write_text("SOME_OTHER_KEY=x\nYARA_PARANOIA_LEVEL=2\n")
    monkeypatch.setattr(openxs_scand, "CONFIG", str(config))
    assert openxs_scand.load_paranoia_level() == 2


def test_load_paranoia_level_ignores_garbage_value(tmp_path, monkeypatch):
    config = tmp_path / "openxs.conf"
    config.write_text("YARA_PARANOIA_LEVEL=not-a-number\n")
    monkeypatch.setattr(openxs_scand, "CONFIG", str(config))
    assert openxs_scand.load_paranoia_level() == 1


def test_handle_answers_when_file_vanishes_during_yara_match(tmp_path, monkeypatch):
    import types
    fake_yara = types.ModuleType("yara")
    fake_yara.Error = type("Error", (Exception,), {})
    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    class VanishingRules:
        def match(self, path, fast=True):
            raise fake_yara.Error(f'could not open file "{path}"')

    target = tmp_path / "cache.tmp"
    target.write_text("<?php echo 1;")
    monkeypatch.setattr(openxs_scand, "_rules", VanishingRules())
    monkeypatch.setattr(openxs_scand, "_ignore_patterns", ([], []), raising=False)
    monkeypatch.setattr(openxs_scand.pmf_scan, "is_ignored", lambda *a: False)

    for query, expected in ((str(target), b"1\n"), ("ALL " + str(target), b"[]\n")):
        sent = []
        handler = openxs_scand.ScanHandler.__new__(openxs_scand.ScanHandler)
        handler.request = types.SimpleNamespace(recv=lambda n, q=query: q.encode(), sendall=sent.append)
        handler.handle()
        assert sent == [expected]
