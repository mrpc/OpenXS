"""Unit tests for disabled_sites.py - which homes the hosting panel has
disabled, and the walk/exclude helpers that skip them."""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import disabled_sites as ds


def test_virtualmin_web_disabled_only(tmp_path):
    d = tmp_path / "domains"
    d.mkdir()
    (d / "1").write_text("dom=off.gr\nhome=/home/off\ndisabled=unix,dns,mail,web,ssl,mysql\n")
    (d / "2").write_text("dom=on.gr\nhome=/home/on\n")
    (d / "3").write_text("dom=mailonly.gr\nhome=/home/mailonly\ndisabled=mail\n")
    assert ds.disabled_homes(str(d), str(tmp_path / "none")) == {"/home/off"}


def test_no_panel_means_nothing_disabled(tmp_path):
    assert ds.disabled_homes(str(tmp_path / "a"), str(tmp_path / "b")) == set()


def test_walk_skips_disabled_home_and_is_disabled(tmp_path):
    for p in ("off/public_html/wp-includes", "on/public_html/wp-includes"):
        (tmp_path / p).mkdir(parents=True)
    homes = {str(tmp_path / "off")}
    seen = [dp for dp, _, _ in ds.walk(str(tmp_path), homes)]
    assert any("/on/" in p for p in seen)
    assert not any("/off" in p for p in seen)
    assert ds.is_disabled(str(tmp_path / "off" / "public_html"), homes)
    assert not ds.is_disabled(str(tmp_path / "offshore"), homes)
    assert list(ds.walk(str(tmp_path / "off"), homes)) == []


def test_exclude_regex_escapes_and_matches_only_under_home():
    rx = ds.exclude_regex({"/home/a.b", "/home/c"})
    assert re.search(rx, "/home/a.b/public_html/")
    assert not re.search(rx, "/home/axb/public_html/")
    assert not re.search(rx, "/home/cc/")
    assert ds.exclude_regex(set()) == ""
