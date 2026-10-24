import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import openxs_collector as c


def test_main_runs_all_jobs_and_reports_status(capsys):
    c.JOBS = [("ok-job", lambda: "did the thing")]
    assert c.main() == 0
    assert "[ok-job] did the thing" in capsys.readouterr().out


def test_main_reports_failure_but_keeps_running_other_jobs(capsys):
    def failing():
        raise RuntimeError("boom")

    calls = []
    c.JOBS = [("broken", failing), ("fine", lambda: calls.append(1) or "ok")]
    assert c.main() == 1  # at least one job failed
    out = capsys.readouterr()
    assert "[broken] FAILED: boom" in out.err
    assert "[fine] ok" in out.out
    assert calls == [1]  # the second job still ran despite the first failing
