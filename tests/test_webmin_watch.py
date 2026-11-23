import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import webmin_watch as w

NOW = time.mktime(time.strptime("2026-11-23 12:00:00", "%Y-%m-%d %H:%M:%S"))


def _mkhome(tmp_path, name):
    home = tmp_path / name
    home.mkdir()
    return home


def test_persistence_first_sighting_baselines_silently(tmp_path, monkeypatch):
    home = _mkhome(tmp_path, "victim")
    (home / ".usermin").mkdir()
    (home / ".usermin" / "changepass").mkdir()
    (home / ".usermin" / "changepass" / "recovery").write_text("legit@example.com")
    monkeypatch.setattr(w, "_homes", lambda: [("victim", str(home))])

    state = {}
    findings = w.check_persistence(state)
    assert findings == []
    assert state["persistence"][f"{home}:.usermin/changepass/recovery"]


def test_persistence_change_after_baseline_is_a_finding(tmp_path, monkeypatch):
    home = _mkhome(tmp_path, "victim")
    (home / ".usermin").mkdir()
    (home / ".usermin" / "changepass").mkdir()
    recovery = home / ".usermin" / "changepass" / "recovery"
    recovery.write_text("")
    monkeypatch.setattr(w, "_homes", lambda: [("victim", str(home))])

    state = {}
    assert w.check_persistence(state) == []  # baseline (empty)

    recovery.write_text("attacker@evil.example")
    findings = w.check_persistence(state)
    assert findings == [("victim", str(home), os.path.join(".usermin", "changepass", "recovery"))]

    # same value again: no repeat finding
    assert w.check_persistence(state) == []


def test_persistence_ignores_symlink_escape(tmp_path, monkeypatch):
    home = _mkhome(tmp_path, "victim")
    secret = tmp_path / "outside_secret"
    secret.write_text("root's secret")
    (home / ".forward").symlink_to(secret)
    monkeypatch.setattr(w, "_homes", lambda: [("victim", str(home))])

    state = {}
    assert w.check_persistence(state) == []
    assert f"{home}:.forward" not in state.get("persistence", {})


def test_persistence_missing_file_tracked_then_cleared(tmp_path, monkeypatch):
    home = _mkhome(tmp_path, "victim")
    forward = home / ".forward"
    monkeypatch.setattr(w, "_homes", lambda: [("victim", str(home))])

    state = {}
    assert w.check_persistence(state) == []  # nothing there yet

    forward.write_text("|/some/pipe")
    assert w.check_persistence(state) == []  # first sighting, baselined

    forward.unlink()
    assert w.check_persistence(state) == []
    assert f"{home}:.forward" not in state["persistence"]


USERMIN_AUTH = 'X.X.X.X - root [29/Jan/2024:15:57:02 +0200] "GET /mailbox/index.cgi?id=INBOX HTTP/1.1" 200 4208\n'
USERMIN_ANON = 'X.X.X.X - - [23/Nov/2026:09:29:38 +0200] "GET /manifest-usermin.json HTTP/1.0" 401 25940\n'


def test_check_logins_parses_both_sample_formats_and_ignores_anon(tmp_path, monkeypatch):
    log = tmp_path / "miniserv.log"
    log.write_text(USERMIN_AUTH.replace("X.X.X.X", "1.2.3.4").replace("29/Jan/2024", "23/Nov/2026")
                   + USERMIN_ANON.replace("X.X.X.X", "9.9.9.9"))
    monkeypatch.setattr(w, "LOGIN_SOURCES", {"Usermin": str(log)})

    state = {}
    findings = w.check_logins(state, now=NOW)
    assert findings == []  # first sighting: baselined
    assert state["logins"]["Usermin:root"] == ["1.2.3.4"]


def test_check_logins_new_ip_after_baseline_is_a_finding(tmp_path, monkeypatch):
    log = tmp_path / "miniserv.log"
    log.write_text('1.2.3.4 - root [23/Nov/2026:10:00:00 +0200] "GET /x HTTP/1.1" 200 1\n')
    monkeypatch.setattr(w, "LOGIN_SOURCES", {"Usermin": str(log)})

    state = {}
    assert w.check_logins(state, now=NOW) == []

    log.write_text('1.2.3.4 - root [23/Nov/2026:11:00:00 +0200] "GET /x HTTP/1.1" 200 1\n'
                    '5.6.7.8 - root [23/Nov/2026:11:00:01 +0200] "GET /x HTTP/1.1" 200 1\n')
    findings = w.check_logins(state, now=NOW)
    assert findings == [("Usermin", "root", "5.6.7.8")]
    # doesn't re-flag on the next run
    assert w.check_logins(state, now=NOW) == []


def test_check_logins_ignores_lines_outside_lookback_window(tmp_path, monkeypatch):
    log = tmp_path / "miniserv.log"
    old_ts = time.strftime("%d/%b/%Y:%H:%M:%S %z", time.localtime(NOW - 48 * 3600))
    log.write_text(f'1.2.3.4 - root [{old_ts}] "GET /x HTTP/1.1" 200 1\n')
    monkeypatch.setattr(w, "LOGIN_SOURCES", {"Usermin": str(log)})
    monkeypatch.setattr(os.path, "getmtime", lambda p: NOW)

    state = {}
    assert w.check_logins(state, now=NOW) == []
    assert "Usermin:root" not in state.get("logins", {})


def test_run_sends_no_mail_on_first_deploy(tmp_path, monkeypatch):
    home = _mkhome(tmp_path, "victim")
    (home / ".forward").write_text("someone@example.com")
    monkeypatch.setattr(w, "_homes", lambda: [("victim", str(home))])
    monkeypatch.setattr(w, "LOGIN_SOURCES", {})
    monkeypatch.setattr(w, "STATE_FILE", str(tmp_path / "state.json"))
    sent = []
    monkeypatch.setattr(w, "_send", lambda conf, subject, body: sent.append(subject))

    status = w.run(now=NOW, conf=dict(w.DEFAULTS))
    assert sent == []
    assert "0 persistence finding(s)" in status


def test_run_alerts_on_a_later_change(tmp_path, monkeypatch):
    home = _mkhome(tmp_path, "victim")
    forward = home / ".forward"
    forward.write_text("someone@example.com")
    monkeypatch.setattr(w, "_homes", lambda: [("victim", str(home))])
    monkeypatch.setattr(w, "LOGIN_SOURCES", {})
    monkeypatch.setattr(w, "STATE_FILE", str(tmp_path / "state.json"))
    sent = []
    monkeypatch.setattr(w, "_send", lambda conf, subject, body: sent.append(subject))

    w.run(now=NOW, conf=dict(w.DEFAULTS))
    assert sent == []

    forward.write_text("attacker@evil.example")
    w.run(now=NOW, conf=dict(w.DEFAULTS))
    assert len(sent) == 1
    assert "persistence file changed for victim" in sent[0]
