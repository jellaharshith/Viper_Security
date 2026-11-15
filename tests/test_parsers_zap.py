import json

from viper.findings.parsers import parse_zap_probe, parse_zap_probe_ex

A = {"action_id": "zap_1", "target": "x.test", "audit_refs": ["h1"]}


def _alert(alert: str, risk: str = "Medium", confidence: str = "High", url: str = "https://x.test/",
           cweid: str = "693") -> str:
    return json.dumps({"tool": "zap_baseline", "alert": alert, "risk": risk,
                       "confidence": confidence, "url": url, "cweid": cweid,
                       "description": "d", "solution": "fix it", "reference": "https://ref"})


def test_zap_alerts_become_findings_with_mapped_severity_and_cwe() -> None:
    out = "\n".join([_alert("X-Content-Type-Options Header Missing", risk="Low"),
                     _alert("SQL Injection", risk="High", confidence="Medium", cweid="89")])
    findings = parse_zap_probe(out, **A)
    assert len(findings) == 2
    by_cwe = {f.cwe[0]: f for f in findings}
    assert by_cwe["CWE-693"].severity == "low" and by_cwe["CWE-693"].confidence == "confirmed"
    # ZAP "Medium" confidence is not deterministic enough -> hypothesis
    assert by_cwe["CWE-89"].severity == "high" and by_cwe["CWE-89"].confidence == "hypothesis"
    assert all(f.source_tool == "zap_baseline" and f.audit_refs == ["h1"] for f in findings)


def test_zap_dedupes_and_skips_malformed() -> None:
    out = "\n".join([_alert("Dup", url="https://x.test/a"), _alert("Dup", url="https://x.test/a"),
                     "not json", json.dumps({"tool": "zap_baseline"})])  # missing fields
    findings, skipped = parse_zap_probe_ex(out, **A)
    assert len(findings) == 1 and skipped >= 1


def test_zap_ignores_other_tools_records() -> None:
    out = json.dumps({"tool": "nuclei", "alert": "x", "risk": "High", "url": "https://x.test/"})
    assert parse_zap_probe(out, **A) == []
