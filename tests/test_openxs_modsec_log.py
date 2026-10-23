import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_modsec_log as m

# Real line shape, confirmed against actual prod-host-3/example logs this
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


def test_daily_counts_buckets_by_date(tmp_path, monkeypatch):
    other_day_line = SAMPLE_LINE.replace(
        "Sat Oct 24 01:43:36.376503 2026", "Sun Oct 25 00:00:00.000000 2026"
    )
    log = tmp_path / "error.log"
    log.write_text((SAMPLE_LINE + "\n") * 2 + other_day_line + "\n")
    monkeypatch.setattr(m, "log_files", lambda: [str(log)])

    counts = m.daily_counts()

    assert counts == {"2026-10-24": 2, "2026-10-25": 1}


def test_daily_counts_skips_unparseable_timestamp(tmp_path, monkeypatch):
    bad_line = SAMPLE_LINE.replace("Sat Oct 24 01:43:36.376503 2026", "not-a-timestamp")
    log = tmp_path / "error.log"
    log.write_text(bad_line + "\n")
    monkeypatch.setattr(m, "log_files", lambda: [str(log)])

    assert m.daily_counts() == {}
