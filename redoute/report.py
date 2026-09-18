from __future__ import annotations
from .auditor import Finding, SEVERITY_ORDER

_BADGE = {"critical": "[CRITICAL]", "high": "[HIGH]    ", "medium": "[MEDIUM]  ", "low": "[LOW]     "}


def render(findings, filename):
    if not findings:
        return f"\nredoute scanned {filename}\nNo vulnerabilities found.\n"
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
    lines = [f"\nredoute scanned {filename}", f"{len(findings)} finding(s):\n"]
    for i, f in enumerate(findings, 1):
        loc = f"line {f.line}" if f.line else "location n/a"
        meta = [loc, f.cwe or "no CWE"]
        if f.test_id:
            meta.append(f.test_id)
        meta.append(f"source: {f.source}")
        lines.append(f"{_BADGE[f.severity]} {i}. {f.title}  ({', '.join(meta)})")
        lines.append(f"    Threat vector: {f.threat_vector}")
        lines.append(f"    How it's exploited: {f.explanation}")
        lines.append(f"    Suggested fix: {f.suggested_fix}\n")
    return "\n".join(lines)
