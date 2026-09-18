from __future__ import annotations
from pathlib import Path
from redoute.static_scan import run_bandit
from redoute.validator import validate_patch

# A private copy of examples/vulnerable.py — see test_static_scan.py for why.
VULNERABLE = Path(__file__).resolve().parent / "fixtures" / "vulnerable.py"

# A path that doesn't exist on disk, used only as the "file being validated"
# label. Gate C stages a copy of the whole project and overwrites this exact
# path with the patch under test, so it must not collide with a real fixture
# path that another test hardcodes assumptions about.
SCRATCH_TARGET = str(VULNERABLE.parent / "scratch_target.py")


def _command_injection_finding():
    findings = run_bandit(str(VULNERABLE))
    return next(f for f in findings if f.test_id == "B605")


def test_validator_rejects_patch_that_does_not_fix_the_vulnerability():
    original = VULNERABLE.read_text()
    target = _command_injection_finding()

    # Claims to fix it, but never touches the vulnerable os.system call.
    broken_patch = original.replace(
        "def run_command(user_input):",
        'def run_command(user_input):\n    # "sanitized" (does nothing)',
    )

    result = validate_patch(original, broken_patch, SCRATCH_TARGET, target)

    assert result.accepted is False
    rescan = next(g for g in result.gates if g.name == "rescan")
    assert rescan.status == "fail"
    exploit = next(g for g in result.gates if g.name == "exploit")
    assert exploit.status == "fail"


def test_validator_accepts_a_genuine_fix():
    original = VULNERABLE.read_text()
    target = _command_injection_finding()

    patched = original.replace("import os", "import os\nimport subprocess").replace(
        'os.system("echo " + user_input)',
        'subprocess.run(["echo", user_input], shell=False)',
    )

    result = validate_patch(original, patched, SCRATCH_TARGET, target)

    assert result.accepted is True
    assert all(g.status != "fail" for g in result.gates)
