import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import install_csf_hook as h

REGEX_SKELETON = """# some header
# Do not edit before this point
1;
"""


def test_detect_access_log_glob_picks_first_matching_candidate(tmp_path, monkeypatch):
    virtualmin_dir = tmp_path / "virtualmin"
    virtualmin_dir.mkdir()
    (virtualmin_dir / "example.com_access_log").write_text("")
    apache_dir = tmp_path / "apache2"
    apache_dir.mkdir()
    (apache_dir / "other_access.log").write_text("")
    monkeypatch.setattr(h, "ACCESS_LOG_GLOB_CANDIDATES", [
        str(virtualmin_dir / "*_access_log"),
        str(apache_dir / "*access*.log"),
    ])
    assert h.detect_access_log_glob() == str(virtualmin_dir / "*_access_log")


def test_detect_access_log_glob_none_when_nothing_matches(tmp_path, monkeypatch):
    monkeypatch.setattr(h, "ACCESS_LOG_GLOB_CANDIDATES", [str(tmp_path / "nothing" / "*.log")])
    assert h.detect_access_log_glob() is None


def test_read_config_value_default_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(h, "OPENXS_CONF", str(tmp_path / "no-such-file"))
    assert h._read_config_value("WP_BRUTE_THRESHOLD", "30") == "30"


def test_read_config_value_reads_set_value(tmp_path, monkeypatch):
    conf = tmp_path / "openxs.conf"
    conf.write_text("EMAIL=root@localhost\nWP_BRUTE_THRESHOLD=50\n")
    monkeypatch.setattr(h, "OPENXS_CONF", str(conf))
    assert h._read_config_value("WP_BRUTE_THRESHOLD", "30") == "50"
    assert h._read_config_value("WP_BRUTE_BAN_SECS", "3600") == "3600"


def test_insert_rule_adds_once_then_skips():
    content, inserted = h._insert_rule(REGEX_SKELETON, "my-marker", "\n\tRULE my-marker\n")
    assert inserted
    assert "RULE" in content
    content2, inserted2 = h._insert_rule(content, "my-marker", "\n\tRULE my-marker\n")
    assert not inserted2
    assert content2.count("RULE") == 1


def test_insert_rule_recognizes_an_existing_manually_added_block():
    manual = REGEX_SKELETON.replace("1;", '\tif (1) { return ("x",$1,"wpbrute","30","80,443","3600","0"); }\n1;')
    content, inserted = h._insert_rule(manual, "wpbrute", "\n\tSHOULD NOT BE ADDED\n")
    assert not inserted
    assert "SHOULD NOT BE ADDED" not in content


def test_insert_rule_noop_when_marker_line_missing():
    content, inserted = h._insert_rule("no marker here\n", "my-marker", "\n\tRULE\n")
    assert not inserted
    assert content == "no marker here\n"


def _fake_run(cmd, **kw):
    class R:
        returncode = 0
        stdout = ""
        stderr = ""
    return R()


def test_main_inserts_both_rules_with_configured_thresholds(tmp_path, monkeypatch, capsys):
    csf_conf = tmp_path / "csf.conf"
    csf_conf.write_text('CUSTOM1_LOG = ""\nCUSTOM2_LOG = ""\n')
    csf_regex = tmp_path / "regex.custom.pm"
    csf_regex.write_text(REGEX_SKELETON)
    openxs_conf = tmp_path / "openxs.conf"
    openxs_conf.write_text("WP_BRUTE_THRESHOLD=50\nWP_BRUTE_BAN_SECS=7200\n")
    vhost_dir = tmp_path / "virtualmin"
    vhost_dir.mkdir()
    (vhost_dir / "example.com_access_log").write_text("")

    monkeypatch.setattr(h, "CSF_CONF", str(csf_conf))
    monkeypatch.setattr(h, "CSF_REGEX", str(csf_regex))
    monkeypatch.setattr(h, "OPENXS_CONF", str(openxs_conf))
    monkeypatch.setattr(h, "ACCESS_LOG_GLOB_CANDIDATES", [str(vhost_dir / "*_access_log")])
    monkeypatch.setattr(h.subprocess, "run", _fake_run)

    h.main()

    conf_text = csf_conf.read_text()
    assert f'CUSTOM2_LOG = "{vhost_dir / "*_access_log"}"' in conf_text
    regex_text = csf_regex.read_text()
    assert '"wpbrute","50","80,443","7200","0"' in regex_text
    assert "openxs-scan" in regex_text

    # re-running is a no-op (no duplicate rules)
    h.main()
    regex_text2 = csf_regex.read_text()
    assert regex_text2.count("wpbrute") == regex_text.count("wpbrute")
    assert regex_text2.count("openxs-scan") == regex_text.count("openxs-scan")


def test_main_noops_when_no_hook_marker_present(tmp_path, monkeypatch, capsys):
    csf_conf = tmp_path / "csf.conf"
    csf_conf.write_text('CUSTOM1_LOG = ""\nCUSTOM2_LOG = ""\n')
    csf_regex = tmp_path / "regex.custom.pm"
    csf_regex.write_text(REGEX_SKELETON)
    marker = tmp_path / "no-csf-hook"
    marker.write_text("")

    monkeypatch.setattr(h, "CSF_CONF", str(csf_conf))
    monkeypatch.setattr(h, "CSF_REGEX", str(csf_regex))
    monkeypatch.setattr(h, "NO_HOOK_MARKER", str(marker))
    monkeypatch.setattr(h.subprocess, "run", _fake_run)

    h.main()

    assert csf_conf.read_text() == 'CUSTOM1_LOG = ""\nCUSTOM2_LOG = ""\n'
    assert csf_regex.read_text() == REGEX_SKELETON
    assert "no-csf-hook" in capsys.readouterr().out


def test_main_skips_wpbrute_rule_when_no_access_log_found(tmp_path, monkeypatch):
    csf_conf = tmp_path / "csf.conf"
    csf_conf.write_text('CUSTOM1_LOG = ""\nCUSTOM2_LOG = ""\n')
    csf_regex = tmp_path / "regex.custom.pm"
    csf_regex.write_text(REGEX_SKELETON)

    monkeypatch.setattr(h, "CSF_CONF", str(csf_conf))
    monkeypatch.setattr(h, "CSF_REGEX", str(csf_regex))
    monkeypatch.setattr(h, "OPENXS_CONF", str(tmp_path / "no-openxs-conf"))
    monkeypatch.setattr(h, "ACCESS_LOG_GLOB_CANDIDATES", [str(tmp_path / "nothing" / "*.log")])
    monkeypatch.setattr(h.subprocess, "run", _fake_run)

    h.main()

    assert "wpbrute" not in csf_regex.read_text()
    assert "openxs-scan" in csf_regex.read_text()
    assert 'CUSTOM2_LOG = ""' in csf_conf.read_text()  # untouched
