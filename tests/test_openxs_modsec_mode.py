import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_modsec_mode as m


def test_regenerate_writes_if_block_per_host(tmp_path, monkeypatch):
    mode_file = tmp_path / "modsec_mode"
    out = tmp_path / "out.conf"
    mode_file.write_text("www.example.com detection\n# a comment\n\n")
    monkeypatch.setattr(m, "MODE_FILE", str(mode_file))
    monkeypatch.setattr(m, "OUTPUT_FILE", str(out))

    entries = m.regenerate()

    assert entries == [("www.example.com", "detection")]
    content = out.read_text()
    assert "HTTP_HOST} == 'www.example.com'" in content
    assert "SecRuleEngine DetectionOnly" in content


def test_star_host_sets_server_wide_default_without_if_condition(tmp_path, monkeypatch):
    mode_file = tmp_path / "modsec_mode"
    out = tmp_path / "out.conf"
    mode_file.write_text("* off\n")
    monkeypatch.setattr(m, "MODE_FILE", str(mode_file))
    monkeypatch.setattr(m, "OUTPUT_FILE", str(out))

    m.regenerate()

    content = out.read_text()
    assert "SecRuleEngine Off" in content
    assert "<If " not in content


def test_invalid_mode_is_skipped(tmp_path, monkeypatch):
    mode_file = tmp_path / "modsec_mode"
    monkeypatch.setattr(m, "MODE_FILE", str(mode_file))
    mode_file.write_text("www.example.com bogus\n")
    assert m.read_modes() == []


def test_no_mode_file_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "MODE_FILE", str(tmp_path / "missing"))
    assert m.read_modes() == []
