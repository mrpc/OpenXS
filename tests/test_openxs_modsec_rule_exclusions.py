import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_modsec_rule_exclusions as m


def test_regenerate_writes_global_target_update(tmp_path, monkeypatch):
    excl = tmp_path / "modsec_rule_exclusions"
    out = tmp_path / "out.conf"
    excl.write_text("930120 ARGS:scope\n# a comment\n\n")
    monkeypatch.setattr(m, "EXCLUSIONS_FILE", str(excl))
    monkeypatch.setattr(m, "OUTPUT_FILE", str(out))

    entries = m.regenerate()

    assert entries == [("930120", "ARGS:scope", None)]
    content = out.read_text()
    assert 'SecRuleUpdateTargetById 930120 "!ARGS:scope"' in content
    assert "<LocationMatch" not in content


def test_regenerate_scopes_to_path_when_given(tmp_path, monkeypatch):
    excl = tmp_path / "modsec_rule_exclusions"
    out = tmp_path / "out.conf"
    excl.write_text("941310 ARGS:notes /el/parent/saveclassified\n")
    monkeypatch.setattr(m, "EXCLUSIONS_FILE", str(excl))
    monkeypatch.setattr(m, "OUTPUT_FILE", str(out))

    entries = m.regenerate()

    assert entries == [("941310", "ARGS:notes", "/el/parent/saveclassified")]
    content = out.read_text()
    assert '<LocationMatch "^/el/parent/saveclassified">' in content
    assert 'SecRuleUpdateTargetById 941310 "!ARGS:notes"' in content


def test_non_numeric_rule_id_is_skipped(tmp_path, monkeypatch):
    excl = tmp_path / "modsec_rule_exclusions"
    monkeypatch.setattr(m, "EXCLUSIONS_FILE", str(excl))
    excl.write_text("notanumber ARGS:scope\n")
    assert m.read_exclusions() == []


def test_no_exclusions_file_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "EXCLUSIONS_FILE", str(tmp_path / "missing"))
    assert m.read_exclusions() == []
