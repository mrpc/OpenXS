import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import sasl_watch as s

NOW = time.mktime(time.strptime("2026-11-09 12:00:00", "%Y-%m-%d %H:%M:%S"))
CONF = dict(s.DEFAULTS)


def sasl(ts, qid, host, ip, user):
    return f"{ts} mx postfix/smtps/smtpd[1]: {qid}: client={host}[{ip}], sasl_method=LOGIN, sasl_username={user}\n"


def test_many_ips_flags_user_but_not_exempt_gmail_or_old_lines():
    lines = [sasl("Nov  9 11:30:00", f"Q{i}", "unknown", f"10.0.0.{i}", "victim") for i in range(11)]
    lines += [sasl("2026-11-09T11:00:00.1+02:00", f"G{i}", f"mail-x{i}.google.com", f"209.85.0.{i}", "info@ex.gr") for i in range(50)]
    lines += [sasl("Nov  7 11:00:00", f"O{i}", "unknown", f"10.1.0.{i}", "old") for i in range(50)]
    findings, _ = s.analyze(lines, CONF, NOW)
    assert list(findings) == ["victim"]
    assert "11 different IPs" in findings["victim"][0]


def test_rate_bounce_and_dead_milter():
    lines = [sasl("Nov  9 11:30:00", f"Q{i}", "a.b", "10.0.0.1", "u") for i in range(101)]
    lines += [f"Nov  9 11:31:00 mx postfix/smtp[2]: Q{i}: to=<x@y>, relay=r, status={'bounced' if i < 40 else 'sent'} (x)\n" for i in range(100)]
    lines.append("Nov  9 11:59:00 mx postfix/smtpd[3]: warning: connect to Milter service unix:/run/greylist.sock: Connection refused\n")
    findings, milters = s.analyze(lines, CONF, NOW)
    assert len(findings["u"]) == 2  # 101 msgs/h + 40% bounced
    assert list(milters) == ["unix:/run/greylist.sock"]


def test_block_user_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(s.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": "check_sasl_access hash:" + str(tmp_path / "m")})())
    m = tmp_path / "m"
    s.block_user("u@x.gr", str(m))
    assert "WARNING" not in s.block_user("u@x.gr", str(m))
    assert m.read_text().count("u@x.gr REJECT") == 1
