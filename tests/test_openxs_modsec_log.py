import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_modsec_log as m

# Real line shape, confirmed against actual prodserver/anotherserver logs this
# session - the hostname/uri field order and surrounding [tag ...]
# repeats varies, which is exactly what broke the first combined-regex
# version (silently captured host=None while still matching overall).
SAMPLE_LINE = (
    '[Sat Oct 24 01:43:36.376503 2026] [security2:error] [pid 1:tid 2] '
    '[client 1.2.3.4:1] [client 1.2.3.4] ModSecurity: Access denied with code 403 '
    '(phase 4). Operator GE matched 4 at TX:outbound_anomaly_score. '
    '[file "/usr/share/modsecurity-crs/rules/RESPONSE-959-BLOCKING-EVALUATION.conf"] '
    '[line "77"] [id "959100"] [msg "Outbound Anomaly Score Exceeded (Total Score: 4)"] '
    '[ver "OWASP_CRS/3.3.4"] [tag "anomaly-evaluation"] [hostname "www.example.com"] '
    '[uri "/index.php"] [unique_id "abc123"]'
)


def test_block_re_matches_real_line_shape():
    m_obj = m.BLOCK_RE.search(SAMPLE_LINE)
    assert m_obj is not None
    assert m_obj.group("id") == "959100"


def test_host_and_uri_extracted_independently():
    # The combined single-regex version silently captured host=None even
    # on a line that genuinely has a [hostname "..."] field - this is the
    # regression this test guards against.
    hm = m.HOST_RE.search(SAMPLE_LINE)
    um = m.URI_RE.search(SAMPLE_LINE)
    assert hm.group(1) == "www.example.com"
    assert um.group(1) == "/index.php"


def test_summarize_groups_and_counts(tmp_path, monkeypatch):
    log = tmp_path / "error.log"
    log.write_text((SAMPLE_LINE + "\n") * 3)
    monkeypatch.setattr(m, "log_files", lambda: [str(log)])

    rows = m.summarize()

    assert len(rows) == 1
    assert rows[0]["count"] == 3
    assert rows[0]["host"] == "www.example.com"
    assert rows[0]["uri"] == "/index.php"
    assert rows[0]["rule_id"] == "959100"
