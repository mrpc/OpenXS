import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_modsec_exclusions as m


def test_regenerate_writes_locationmatch_per_path(tmp_path, monkeypatch):
    excl = tmp_path / "modsec_exclusions"
    out = tmp_path / "out.conf"
    excl.write_text("/admin\n# a comment\n\n/ClientVitals\n")
    monkeypatch.setattr(m, "EXCLUSIONS_FILE", str(excl))
    monkeypatch.setattr(m, "OUTPUT_FILE", str(out))

    paths = m.regenerate()

    assert paths == ["/admin", "/ClientVitals"]
    content = out.read_text()
    assert '<LocationMatch "^/admin">' in content
    assert '<LocationMatch "^/ClientVitals">' in content
    assert content.count("SecRuleEngine Off") == 2


def test_regenerate_escapes_regex_metacharacters(tmp_path, monkeypatch):
    excl = tmp_path / "modsec_exclusions"
    out = tmp_path / "out.conf"
    excl.write_text("/a.b(c)\n")
    monkeypatch.setattr(m, "EXCLUSIONS_FILE", str(excl))
    monkeypatch.setattr(m, "OUTPUT_FILE", str(out))

    m.regenerate()

    content = out.read_text()
    assert r"^/a\.b\(c\)" in content


def test_no_exclusions_file_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "EXCLUSIONS_FILE", str(tmp_path / "missing"))
    assert m.read_exclusions() == []
