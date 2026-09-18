from __future__ import annotations
import os, shutil, subprocess, sys, tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
from .auditor import Finding, SEVERITY_ORDER, _same_class
from .static_scan import run_bandit

EXPLOIT_TIMEOUT = 30
TEST_TIMEOUT = 120

# Gate C runs the project's own test suite, which (once tests/ exists) can
# itself call validate_patch(). Without this guard that would spawn a
# pytest subprocess whose tests spawn another pytest subprocess, forever.
# It's set on the nested subprocess's environment only, so recursion is
# cut off at one level deep rather than growing unbounded.
_RECURSION_GUARD_ENV = "REDOUTE_VALIDATING"


@dataclass
class GateResult:
    name: str
    status: str  # "pass" | "fail" | "skipped"
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationResult:
    accepted: bool
    gates: list[GateResult]

    def as_dict(self) -> dict[str, Any]:
        return {"accepted": self.accepted, "gates": [g.as_dict() for g in self.gates]}


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _finding_key(f: Finding) -> str:
    return f.test_id or f"title:{f.title}"


def run_rescan_gate(baseline_findings: list[Finding], finding: Finding, patched_path: Path) -> GateResult:
    """Gate A: Bandit must no longer report this finding, and must not
    report any new high/critical finding that wasn't already there."""
    try:
        patched_findings = run_bandit(str(patched_path))
    except Exception as e:
        return GateResult("rescan", "fail", f"Bandit could not run on the patched file: {e}")

    still_present = any(
        (f.test_id == finding.test_id) if finding.test_id else _same_class(finding, f)
        for f in patched_findings
    )
    if still_present:
        return GateResult(
            "rescan", "fail",
            f"Bandit still reports {finding.test_id or finding.title!r} in the patched file",
        )

    baseline_keys = {_finding_key(f) for f in baseline_findings}
    new_high_crit = [
        f for f in patched_findings
        if SEVERITY_ORDER.get(f.severity, 0) >= SEVERITY_ORDER["high"]
        and _finding_key(f) not in baseline_keys
    ]
    if new_high_crit:
        names = ", ".join(f"{f.test_id or f.title} (line {f.line})" for f in new_high_crit)
        return GateResult("rescan", "fail", f"patch introduces new high/critical finding(s): {names}")

    return GateResult("rescan", "pass", "original issue no longer reported; no new high/critical findings")


def _find_poc(finding: Finding, pocs_dir: Path) -> Path | None:
    candidates = []
    if finding.test_id:
        candidates.append(pocs_dir / f"poc_{finding.test_id.lower()}.py")
    if finding.cwe:
        num = finding.cwe.split("-")[-1]
        candidates.append(pocs_dir / f"poc_cwe_{num}.py")
    return next((c for c in candidates if c.is_file()), None)


def run_exploit_gate(finding: Finding, patched_path: Path, pocs_dir: Path) -> GateResult:
    """Gate B: if a PoC exists for this finding, it must fail to exploit
    the patched file. PoC convention: exit 0 = exploit succeeded (still
    vulnerable), exit 1 = exploit blocked (patched), anything else = error."""
    poc = _find_poc(finding, pocs_dir)
    if poc is None:
        return GateResult("exploit", "skipped", "not validated by exploit: no PoC available for this finding")

    # Best-effort isolation: minimal environment, a throwaway cwd, and a
    # timeout. True network denial needs OS-level sandboxing, which is out
    # of scope for this prototype.
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": ""}
    try:
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, str(poc), str(patched_path)],
                capture_output=True, text=True, timeout=EXPLOIT_TIMEOUT,
                cwd=tmp, env=env,
            )
    except subprocess.TimeoutExpired:
        return GateResult("exploit", "fail", "PoC timed out")
    except OSError as e:
        return GateResult("exploit", "fail", f"could not run PoC: {e}")

    if proc.returncode == 1:
        return GateResult("exploit", "pass", "PoC could not exploit the patched file")
    if proc.returncode == 0:
        return GateResult("exploit", "fail", "PoC still exploits the patched file")
    detail = (proc.stderr or proc.stdout).strip()[-300:]
    return GateResult("exploit", "fail", f"PoC errored (exit {proc.returncode}): {detail}")


def _find_tests_dir(project_root: Path) -> Path | None:
    candidate = project_root / "tests"
    return candidate if candidate.is_dir() else None


def run_tests_gate(project_root: Path, target_path: Path, patched_text: str) -> GateResult:
    """Gate C: if the project has a tests/ dir, run it against a staged
    copy of the project with the target file swapped for the patch."""
    if os.environ.get(_RECURSION_GUARD_ENV):
        return GateResult("tests", "skipped", "skipped to avoid recursive validation (already inside a Gate C run)")

    tests_dir = _find_tests_dir(project_root)
    if tests_dir is None:
        return GateResult("tests", "skipped", "no tests to run")

    try:
        rel_target = target_path.resolve().relative_to(project_root.resolve())
    except ValueError:
        return GateResult("tests", "skipped", "target file is outside the project, cannot stage tests")

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp) / "project"
            shutil.copytree(
                project_root, tmp_root,
                ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", "patches", ".pytest_cache", "*.egg-info"),
            )
            (tmp_root / rel_target).write_text(patched_text, encoding="utf-8")
            env = dict(os.environ, **{_RECURSION_GUARD_ENV: "1"})
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "tests", "-q"],
                cwd=tmp_root, capture_output=True, text=True, timeout=TEST_TIMEOUT, env=env,
            )
    except subprocess.TimeoutExpired:
        return GateResult("tests", "fail", "test suite timed out")
    except OSError as e:
        return GateResult("tests", "fail", f"could not run tests: {e}")

    if proc.returncode == 0:
        return GateResult("tests", "pass", "test suite passed against the patched file")
    tail = (proc.stdout or proc.stderr).strip()[-500:]
    return GateResult("tests", "fail", f"test suite failed (exit {proc.returncode}): {tail}")


def validate_patch(
    original_text: str,
    patched_text: str,
    filename: str,
    finding: Finding,
    project_root: Path | None = None,
) -> ValidationResult:
    """Validate a proposed patch through gates A (re-scan), B (exploit),
    and C (tests) without ever touching the user's real file. A patch is
    accepted only if every applicable gate passes; a gate that errors is
    captured as a failed gate rather than raised."""
    project_root = project_root or _project_root()
    target_path = Path(filename)
    target_name = target_path.name

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        original_path = tmp_dir / f"baseline_{target_name}"
        patched_path = tmp_dir / f"patched_{target_name}"
        original_path.write_text(original_text, encoding="utf-8")
        patched_path.write_text(patched_text, encoding="utf-8")

        baseline_findings = run_bandit(str(original_path))
        gate_a = run_rescan_gate(baseline_findings, finding, patched_path)
        gate_b = run_exploit_gate(finding, patched_path, project_root / "examples" / "pocs")

    gate_c = run_tests_gate(project_root, target_path, patched_text)

    gates = [gate_a, gate_b, gate_c]
    accepted = all(g.status != "fail" for g in gates)
    return ValidationResult(accepted=accepted, gates=gates)
