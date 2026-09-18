from __future__ import annotations
from redoute.auditor import Auditor, Finding


def _sample_static_findings() -> list[Finding]:
    return [
        Finding(
            file="x.py", line=5, severity="high", title="Some issue",
            threat_vector="", explanation="", suggested_fix="",
            cwe="CWE-78", source="static", test_id="B605",
        ),
    ]


def test_parse_triage_falls_back_on_non_json_response():
    static_findings = _sample_static_findings()
    raw = "I looked at the file and it seems fine, no issues found."
    result = Auditor._parse_triage(raw, static_findings, "x.py")
    assert result == static_findings


def test_parse_triage_falls_back_on_truncated_json():
    static_findings = _sample_static_findings()
    raw = '```json\n[{"static_index": 1, "verdict": "confirmed", "line": 5'
    result = Auditor._parse_triage(raw, static_findings, "x.py")
    assert result == static_findings


def test_parse_triage_confirms_and_merges_a_static_finding():
    static_findings = _sample_static_findings()
    raw = """[
        {"static_index": 1, "verdict": "confirmed", "line": 5, "severity": "high",
         "title": "Some issue", "threat_vector": "attacker controlled input",
         "explanation": "explained", "suggested_fix": "fix it", "cwe": "CWE-78",
         "reason": "real sink"}
    ]"""
    result = Auditor._parse_triage(raw, static_findings, "x.py")
    assert len(result) == 1
    assert result[0].source == "static+llm"
    assert result[0].threat_vector == "attacker controlled input"
