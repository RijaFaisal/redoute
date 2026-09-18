from __future__ import annotations
import json, subprocess
from .auditor import Finding

_SEVERITY_MAP = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}


def run_bandit(path: str, timeout: int = 60) -> list[Finding]:
    """Run Bandit on a single file and return its issues as Findings.
    Returns [] if Bandit isn't installed, times out, or produces no
    parseable results, rather than raising."""
    try:
        proc = subprocess.run(
            ["bandit", "-f", "json", "-q", path],
            capture_output=True, text=True, timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []

    if not proc.stdout.strip():
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    results = data.get("results")
    if not isinstance(results, list):
        return []

    findings: list[Finding] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        severity = _SEVERITY_MAP.get(str(item.get("issue_severity", "")).upper(), "medium")

        cwe = None
        cwe_info = item.get("issue_cwe")
        if isinstance(cwe_info, dict) and cwe_info.get("id"):
            cwe = f"CWE-{cwe_info['id']}"

        findings.append(Finding(
            file=item.get("filename") or path,
            line=item.get("line_number"),
            severity=severity,
            title=item.get("issue_text", "Unspecified issue"),
            threat_vector="",
            explanation="",
            suggested_fix="",
            cwe=cwe,
            source="static",
            test_id=item.get("test_id"),
        ))
    return findings
