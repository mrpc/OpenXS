import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import sasl_watch as s

NOW = time.mktime(time.strptime("2026-11-09 12:00:00", "%Y-%m-%d %H:%M:%S"))
CONF = dict(s.DEFAULTS)


@pytest.fixture(autouse=True)
def _no_real_system_files(tmp_path, monkeypatch):
    # A block now also touches Dovecot/Usermin files and home dirs; keep
    # every test away from the real ones.
    monkeypatch.setattr(s, "DOVECOT_DENY_FILE", str(tmp_path / "no-dovecot" / "openxs_blocked"))
    monkeypatch.setattr(s, "USERMIN_CONF", str(tmp_path / "no-usermin" / "miniserv.conf"))
    monkeypatch.setattr(s.pwd, "getpwnam", lambda n: (_ for _ in ()).throw(KeyError(n)))


def sasl(ts, qid, host, ip, user):
    return f"{ts} mx postfix/smtps/smtpd[1]: {qid}: client={host}[{ip}], sasl_method=LOGIN, sasl_username={user}\n"


def test_many_ips_flags_user_but_not_exempt_gmail_or_old_lines():
    lines = [sasl("Nov  9 11:30:00", f"Q{i}", "unknown", f"10.0.0.{i}", "victim") for i in range(11)]
    lines += [sasl("2026-11-09T11:00:00.1+02:00", f"G{i}", f"mail-x{i}.google.com", f"209.85.0.{i}", "info@ex.gr") for i in range(50)]
    lines += [sasl("Nov  7 11:00:00", f"O{i}", "unknown", f"10.1.0.{i}", "old") for i in range(50)]
    findings, _, _, _ = s.analyze(lines, CONF, NOW)
    assert list(findings) == ["victim"]
    assert "11 different IPs" in findings["victim"][0]


def test_rate_bounce_and_dead_milter():
    lines = [sasl("Nov  9 11:30:00", f"Q{i}", "a.b", "10.0.0.1", "u") for i in range(101)]
    lines += [f"Nov  9 11:31:00 mx postfix/smtp[2]: Q{i}: to=<x@y>, relay=r, status={'bounced' if i < 40 else 'sent'} (x)\n" for i in range(100)]
    lines.append("Nov  9 11:59:00 mx postfix/smtpd[3]: warning: connect to Milter service unix:/run/greylist.sock: Connection refused\n")
    findings, milters, _, _ = s.analyze(lines, CONF, NOW)
    assert len(findings["u"]) == 2  # 101 msgs/h + 40% bounced
    assert list(milters) == ["unix:/run/greylist.sock"]


def test_block_user_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(s.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": "check_sasl_access hash:" + str(tmp_path / "m")})())
    m = tmp_path / "m"
    s.block_user(["u@x.gr"], str(m))
    assert "WARNING" not in s.block_user(["u@x.gr"], str(m))
    assert m.read_text().count("u@x.gr REJECT") == 1


def _setup(tmp_path, monkeypatch, shadow_hash="$6$a"):
    monkeypatch.setattr(s, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(s, "REPORT_FILE", str(tmp_path / "report.json"))
    monkeypatch.setattr(s, "SHADOW_FILE", str(tmp_path / "shadow"))
    monkeypatch.setattr(s, "_postmap", lambda p: None)
    sent = []
    monkeypatch.setattr(s, "_send", lambda c, sub, b: sent.append(sub))
    (tmp_path / "shadow").write_text(f"victim:{shadow_hash}:1::\n")
    log = tmp_path / "mail.log"
    log.write_text("")
    conf = dict(s.DEFAULTS, MAIL_LOG=str(log), SASL_WATCH_MAP=str(tmp_path / "map"), SASL_WATCH_AUTOBLOCK="1")
    (tmp_path / "map").write_text("victim REJECT x\n")
    state = {"blocked": {"victim": {"since": NOW, "reason": "r", "pw": s.password_fingerprint("victim")}}}
    s._save_state(state)
    return conf, sent


def test_temporary_unblock_reblocks_after_expiry(tmp_path, monkeypatch):
    conf, sent = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(s.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": ""})())
    assert "for 2h" in s.cmd_unblock("victim", 2, conf, now=NOW)
    assert s._map_users(conf["SASL_WATCH_MAP"]) == []
    s.run(now=NOW + 3600, conf=conf)
    assert s._map_users(conf["SASL_WATCH_MAP"]) == []
    s.run(now=NOW + 3 * 3600, conf=conf)
    assert s._map_users(conf["SASL_WATCH_MAP"]) == ["victim"]
    assert "until" not in s._load_state()["blocked"]["victim"]


def test_password_change_alone_keeps_block_by_default(tmp_path, monkeypatch):
    conf, sent = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(s.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": ""})())
    s.cmd_unblock("victim", 2, conf, now=NOW)
    (tmp_path / "shadow").write_text("victim:$6$new:1::\n")
    s.run(now=NOW + 3 * 3600, conf=conf)
    assert s._map_users(conf["SASL_WATCH_MAP"]) == ["victim"]


def test_password_change_releases_block_when_enabled(tmp_path, monkeypatch):
    conf, sent = _setup(tmp_path, monkeypatch)
    conf["SASL_WATCH_UNBLOCK_ON_PWCHANGE"] = "1"
    (tmp_path / "shadow").write_text("victim:$6$new:1::\n")
    s.run(now=NOW, conf=conf)
    assert s._map_users(conf["SASL_WATCH_MAP"]) == []
    assert "victim" not in s._load_state()["blocked"]
    assert any("password changed" in x for x in sent)


def test_notice_goes_to_mailbox_and_domain_contact(tmp_path, monkeypatch):
    d = tmp_path / "domains"
    d.mkdir()
    (d / "123").write_text("dom=ex.gr\nuser=exgr\nemailto=owner@other.gr\n")
    monkeypatch.setattr(s, "VIRTUALMIN_DOMAINS_DIR", str(d))
    assert s.notice_recipients(["info@ex.gr"], CONF) == ["info@ex.gr", "owner@other.gr"]
    assert s.notice_recipients(["exgr"], CONF) == ["owner@other.gr"]
    assert s.notice_recipients(["nobody"], CONF) == [CONF["EMAIL"]]


def test_realm_variants_fold_into_one_account_and_unblock_together(tmp_path, monkeypatch):
    conf, sent = _setup(tmp_path, monkeypatch)
    (tmp_path / "shadow").write_text("victim:$6$a:1::\nbox@ex.gr:$6$b:1::\n")
    assert s.account("victim@ex.gr") == "victim"   # saslauthd -r realm
    assert s.account("box@ex.gr") == "box@ex.gr"   # Virtualmin user@domain Unix user
    lines = [sasl("Nov  9 11:30:00", f"Q{i}", "unknown", f"10.0.0.{i}", "victim" if i % 2 else "victim@ex.gr") for i in range(12)]
    findings, _, variants, _ = s.analyze(lines, CONF, NOW)
    assert list(findings) == ["victim"] and variants["victim"] == {"victim", "victim@ex.gr"}
    (tmp_path / "map").write_text("victim REJECT x\nvictim@ex.gr REJECT x\nother REJECT x\n")
    assert s.cmd_unblock("victim@ex.gr", 0, conf, now=NOW) == "victim unblocked"
    assert s._map_users(conf["SASL_WATCH_MAP"]) == ["other"]


def test_stats_and_failed_logins_and_manual_block(tmp_path, monkeypatch):
    conf, sent = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(s.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": ""})())
    lines = [sasl("Nov  9 11:30:00", "Q1", "unknown", "10.0.0.1", "a"),
             sasl("Nov  9 11:31:00", "Q2", "mail-x.google.com", "209.85.0.1", "a"),
             "Nov  9 11:32:00 mx postfix/smtpd[9]: warning: unknown[10.9.9.9]: SASL LOGIN authentication failed: UGFzc3dvcmQ6, sasl_username=b@x.gr\n"]
    _, _, _, st = s.analyze(lines, CONF, NOW)
    a = st["accounts"]["a"]
    assert (a["msgs"], a["ips"], a["exempt_msgs"], a["msgs_1h"]) == (2, 1, 1, 2)
    assert st["failed"] == {"b@x.gr": {"count": 1, "ips": 1}}
    (tmp_path / "map").write_text("")
    s._save_state({})
    assert s.cmd_block("someone", conf, now=NOW).startswith("someone blocked")
    assert s._map_users(conf["SASL_WATCH_MAP"]) == ["someone"]
    s.run(now=NOW, conf=conf)
    assert "generated" in s.json.load(open(tmp_path / "report.json"))


def test_forwarded_unauthenticated_rejects_counted():
    def bounce(qid, orig, code):
        return (f"Nov  9 11:40:00 mx postfix/smtp[5]: {qid}: to=<x@gmail.com>, {orig}relay=gmail-smtp-in.l.google.com[1.2.3.4]:25, "
                f"delay=1, dsn=5.7.26, status=bounced (host gmail-smtp-in.l.google.com[1.2.3.4] said: {code} "
                "This mail has been blocked because the sender is unauthenticated.)\n")
    lines = [bounce("F1", "orig_to=<info@ex.gr>, ", "550-5.7.26"), bounce("F2", "orig_to=<info@ex.gr>, ", "550-5.7.26"),
             bounce("F3", "orig_to=<sales@ex.gr>, ", "550-5.7.26"),
             bounce("D1", "", "550-5.7.26"),                        # direct, not forwarded
             bounce("F4", "orig_to=<info@ex.gr>, ", "550-5.7.1")]  # other reason
    _, _, _, st = s.analyze(lines, CONF, NOW)
    assert st["fwd_unauth_rejected"] == {"count": 3, "top": [("info@ex.gr", 2), ("sales@ex.gr", 1)]}


def test_block_locks_imap_usermin_recovery_and_unblock_undoes(tmp_path, monkeypatch):
    # Found live 2026-11-10: the SMTP map alone left the stolen password
    # working for IMAP (35 IPs) and Usermin, where a recovery address was set.
    dove = tmp_path / "openxs_blocked"
    dove.write_text("other\n")
    um = tmp_path / "miniserv.conf"
    um.write_text("port=20000\ndenyusers=baduser\npidfile=/var/usermin/miniserv.pid\n")
    um.chmod(0o600)
    home = tmp_path / "home"
    rec = home / ".usermin" / "changepass" / "recovery"
    rec.parent.mkdir(parents=True)
    rec.write_text("attacker@gmail.example\n")
    (tmp_path / "shadow").write_text("victim:$6$a:1::\n")
    monkeypatch.setattr(s, "SHADOW_FILE", str(tmp_path / "shadow"))
    monkeypatch.setattr(s, "DOVECOT_DENY_FILE", str(dove))
    monkeypatch.setattr(s, "USERMIN_CONF", str(um))
    monkeypatch.setattr(s.pwd, "getpwnam", lambda n: type("P", (), {"pw_dir": str(home)})() if n == "victim" else (_ for _ in ()).throw(KeyError(n)))
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        out = "check_sasl_access hash:" + str(tmp_path / "map") if cmd[0] == "postconf" else ("2" if cmd[0] == "perl" else "")
        return type("R", (), {"stdout": out, "returncode": 0})()

    monkeypatch.setattr(s.subprocess, "run", fake_run)
    result = s.block_user(["victim", "victim@ex.gr"], str(tmp_path / "map"))

    assert result.startswith("AUTO-BLOCKED")
    assert dove.read_text().split() == ["other", "victim", "victim@ex.gr"]
    assert ["doveadm", "kick", "victim@ex.gr"] in calls
    assert "denyusers=baduser victim" in um.read_text()
    assert (um.stat().st_mode & 0o777) == 0o600
    assert ["systemctl", "reload", "usermin"] in calls
    perl = next(c for c in calls if c[0] == "perl")
    assert perl[4] == "/var/usermin/sessiondb" and "victim" in perl[5:]
    assert "2 session(s) ended" in result
    assert not rec.exists()
    backup = next(rec.parent.glob("recovery.openxs-*"))
    assert backup.read_text() == "attacker@gmail.example\n"
    assert "attacker@gmail.example" in result
    assert ["systemctl", "try-restart", "saslauthd"] in calls

    # idempotent: a second block changes nothing
    s.block_user(["victim", "victim@ex.gr"], str(tmp_path / "map"))
    assert dove.read_text().split() == ["other", "victim", "victim@ex.gr"]
    assert um.read_text().count("victim") == 1

    monkeypatch.setattr(s, "_postmap", lambda p: None)
    notes = s.remove_from_map("victim", str(tmp_path / "map"))
    assert dove.read_text().split() == ["other"]
    assert "denyusers=baduser\n" in um.read_text() and "victim" not in um.read_text()
    assert notes == ["IMAP/POP re-enabled", "Usermin re-enabled"]
    assert backup.exists() and not rec.exists()  # the recovery address is never put back


def test_empty_recovery_file_is_left_alone(tmp_path, monkeypatch):
    # Virtualmin creates empty ones on every migration.
    rec = tmp_path / ".usermin" / "changepass" / "recovery"
    rec.parent.mkdir(parents=True)
    rec.write_text("")
    monkeypatch.setattr(s.pwd, "getpwnam", lambda n: type("P", (), {"pw_dir": str(tmp_path)})())
    assert s._remove_recovery(["x@d.gr"], NOW) is None
    assert rec.exists()


def test_failing_step_does_not_stop_the_others(tmp_path, monkeypatch):
    dove = tmp_path / "openxs_blocked"
    dove.write_text("")
    monkeypatch.setattr(s, "DOVECOT_DENY_FILE", str(dove))
    monkeypatch.setattr(s, "_usermin_set", lambda names, add: 1 / 0)
    monkeypatch.setattr(s.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": "", "returncode": 0})())
    notes = s.lock_other_access(["u"])
    assert notes[0] == "IMAP/POP denied, sessions kicked"
    assert notes[1].startswith("Usermin FAILED: division by zero")
    assert notes[-1].startswith("saslauthd restarted")


def test_recovery_symlink_is_not_followed(tmp_path, monkeypatch):
    # The account owns ~/.usermin: a symlink must not make root read
    # another file into the alert, or rename it.
    secret = tmp_path / "secret"
    secret.write_text("root:$6$hash\n")
    d = tmp_path / ".usermin" / "changepass"
    d.mkdir(parents=True)
    (d / "recovery").symlink_to(secret)
    monkeypatch.setattr(s.pwd, "getpwnam", lambda n: type("P", (), {"pw_dir": str(tmp_path)})())
    assert s._remove_recovery(["x"], NOW) is None
    assert secret.read_text() == "root:$6$hash\n" and (d / "recovery").is_symlink()
