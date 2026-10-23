"""Unit tests for apt_security_check.py's own parsing logic (the actual
apt-get calls are mocked - no real package manager interaction in tests)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import apt_security_check as asc


SAMPLE_OUTPUT = """Reading package lists...
Building dependency tree...
Inst libclamav12 [1.4.3+dfsg-1~deb12u2] (1.4.6+dfsg-0+deb12u1 Debian-Security:12/oldstable-security [amd64])
Inst curl [7.88.1-10] (7.88.1-10+deb12u8 Debian:12/stable [amd64])
Conf libclamav12 (1.4.6+dfsg-0+deb12u1 Debian-Security:12/oldstable-security [amd64])
"""


class FakeResult:
    def __init__(self, stdout):
        self.stdout = stdout


def test_pending_updates_classifies_security_vs_regular(monkeypatch):
    monkeypatch.setattr(asc.subprocess, "run", lambda *a, **k: FakeResult(SAMPLE_OUTPUT))
    updates = asc.pending_updates(refresh=False)
    assert len(updates) == 2
    security = [u for u in updates if u[3]]
    regular = [u for u in updates if not u[3]]
    assert [u[0] for u in security] == ["libclamav12"]
    assert [u[0] for u in regular] == ["curl"]


def test_pending_updates_ignores_conf_lines(monkeypatch):
    monkeypatch.setattr(asc.subprocess, "run", lambda *a, **k: FakeResult(SAMPLE_OUTPUT))
    updates = asc.pending_updates(refresh=False)
    assert all(u[0] != "libclamav12" or True for u in updates)  # Conf line shouldn't add a second libclamav12 entry
    assert sum(1 for u in updates if u[0] == "libclamav12") == 1


def test_pending_updates_handles_apt_failure_gracefully(monkeypatch):
    def raise_err(*a, **k):
        raise FileNotFoundError("apt-get not found")
    monkeypatch.setattr(asc.subprocess, "run", raise_err)
    assert asc.pending_updates(refresh=False) == []


def test_pending_updates_empty_output(monkeypatch):
    monkeypatch.setattr(asc.subprocess, "run", lambda *a, **k: FakeResult(""))
    assert asc.pending_updates(refresh=False) == []
