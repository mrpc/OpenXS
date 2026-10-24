"""Unit test for split_scan_results.py's severity-tiering and
new-findings-only filtering for heuristic/fs."""
import os
import subprocess
import sys

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")


def run(results_path, new_findings_path, out_prefix):
    proc = subprocess.run(
        [sys.executable, os.path.join(TOOLS, "split_scan_results.py"),
         str(results_path), str(new_findings_path), str(out_prefix)],
        capture_output=True, text=True, check=True,
    )
    return dict(pair.split("=") for pair in proc.stdout.split())


def test_split_scan_results_tiers_no_new_findings_file(tmp_path):
    # Missing new_findings file = don't filter at all (every heuristic/fs
    # finding counts) - the safe fallback for an older pmf_scan.py or a
    # manual scan that never wrote one.
    results = tmp_path / "scan_results.txt"
    results.write_text(
        "/home/x/shell.php\tKnown exploit backdoor\n"
        "/home/x/a.php\tObfuscatedPhp\n"
        "/home/x/b.php\tsymlink\n"
        "/home/x/c.php\tmalware.found (ClamAV)\n"
    )
    out_prefix = tmp_path / "out"
    counts = run(results, tmp_path / "no_such_file.txt", out_prefix)
    assert counts == {"serious": "2", "heuristic": "1", "fs": "1"}
    assert "shell.php" in (tmp_path / "out.serious.txt").read_text()
    assert "malware.found" in (tmp_path / "out.serious.txt").read_text()
    assert "a.php" in (tmp_path / "out.heuristic.txt").read_text()
    assert "b.php" in (tmp_path / "out.fs.txt").read_text()


def test_split_scan_results_filters_heuristic_fs_to_new_only(tmp_path):
    # serious always comes through in full even if not "new" - an
    # unresolved backdoor should keep nagging, not go quiet.
    results = tmp_path / "scan_results.txt"
    results.write_text(
        "/home/x/shell.php\tKnown exploit backdoor\n"
        "/home/x/a.php\tObfuscatedPhp\n"
        "/home/x/old.php\tDodgyPhp\n"
        "/home/x/b.php\tsymlink\n"
    )
    new_findings = tmp_path / "new_findings.txt"
    new_findings.write_text("/home/x/a.php\tObfuscatedPhp\n")  # old.php and b.php NOT new
    out_prefix = tmp_path / "out"
    counts = run(results, new_findings, out_prefix)
    assert counts == {"serious": "1", "heuristic": "1", "fs": "0"}
    assert "a.php" in (tmp_path / "out.heuristic.txt").read_text()
    assert not os.path.exists(tmp_path / "out.fs.txt")


def test_split_scan_results_empty_input_writes_nothing(tmp_path):
    results = tmp_path / "scan_results.txt"
    results.write_text("")
    out_prefix = tmp_path / "out"
    counts = run(results, tmp_path / "new_findings.txt", out_prefix)
    assert counts == {"serious": "0", "heuristic": "0", "fs": "0"}
    assert not os.path.exists(str(out_prefix) + ".serious.txt")
