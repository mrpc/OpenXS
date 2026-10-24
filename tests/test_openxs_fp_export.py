import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_fp_export as export


def test_render_markdown_empty():
    assert "No false positives" in export.render_markdown([])


def test_render_markdown_escapes_pipe_in_path():
    rows = [(1792900000.0, "modsec", "/a|b", "930120", "rule exclusion applied")]
    out = export.render_markdown(rows)
    assert "/a\\|b" in out
    assert "930120" in out
    assert "| modsec |" in out


def test_render_markdown_dashes_when_no_action_taken():
    rows = [(1792900000.0, "oldversion", "/home/site/composer.lock", "acme/pkg", None)]
    out = export.render_markdown(rows)
    assert out.strip().endswith("| - |")
