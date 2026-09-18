from __future__ import annotations
from pathlib import Path
from redoute.static_scan import run_bandit

# A private copy of examples/vulnerable.py, not the file itself: redoute's
# own `patch` command can rewrite examples/vulnerable.py in Gate C's staged
# test run, which would otherwise invalidate the exact findings asserted
# on here purely because of file-path reuse.
VULNERABLE = Path(__file__).resolve().parent / "fixtures" / "vulnerable.py"


def test_run_bandit_finds_sql_and_command_injection():
    findings = run_bandit(str(VULNERABLE))
    by_test_id = {f.test_id: f for f in findings}

    assert "B608" in by_test_id
    sql = by_test_id["B608"]
    assert sql.line == 7
    assert sql.severity == "medium"
    assert sql.cwe == "CWE-89"
    assert sql.source == "static"

    assert "B605" in by_test_id
    cmd = by_test_id["B605"]
    assert cmd.line == 12
    assert cmd.severity == "high"
    assert cmd.cwe == "CWE-78"
    assert cmd.source == "static"


def test_run_bandit_returns_empty_list_for_missing_binary(monkeypatch):
    import subprocess
    from redoute import static_scan

    def fake_run(*args, **kwargs):
        raise FileNotFoundError("bandit not found")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert static_scan.run_bandit(str(VULNERABLE)) == []
