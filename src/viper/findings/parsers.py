"""Deterministic parsers: tool output -> list[Finding]. Pure functions, no I/O, no LLM.

Anything that does not match a strict line pattern is ignored, so prose (or injected
instructions) in tool output can never become a finding.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from viper.findings.models import Finding, Severity

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_NMAP_PORT = re.compile(
    r"^(?P<port>\d{1,5})/(?P<proto>tcp|udp|sctp)\s+(?P<state>open\|filtered|open)\s+"
    r"(?P<service>\S+)(?:\s+(?P<version>.*))?$"
)
# Services whose protocol sends credentials/data unencrypted.
_CLEARTEXT = {"telnet", "ftp", "rlogin", "rsh", "rexec", "tftp"}

_NUCLEI_TEXT = re.compile(
    r"^(?:\[\d{4}-\d\d-\d\d[^\]]*\]\s+)?"  # optional timestamp prefix
    r"\[(?P<tpl>[^\]]+)\]\s+\[(?P<proto>[^\]]+)\]\s+\[(?P<sev>[^\]]+)\]\s+"
    r"(?P<matched>\S+)(?:\s+(?P<extra>.*))?$"
)
_NUCLEI_SEVERITIES: dict[str, Severity] = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "info",
}


def _fid(tool: str, action_id: str, key: str) -> str:
    return "f-" + hashlib.sha256(f"{tool}|{action_id}|{key}".encode()).hexdigest()[:12]


def _clean(text: str) -> list[str]:
    return [ln.strip() for ln in _ANSI.sub("", text).splitlines() if ln.strip()]


def parse_nmap(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for line in _clean(output):
        m = _NMAP_PORT.match(line)
        if not m or int(m["port"]) > 65535:
            continue
        port, proto, state, service = m["port"], m["proto"], m["state"], m["service"]
        cleartext = service.lower().rstrip("?") in _CLEARTEXT
        severity: Severity = "low" if cleartext else "info"
        rationale = (
            f"{service} transmits data unencrypted; exposure of an open port raises risk."
            if cleartext
            else "An open port is attack surface, not by itself a vulnerability."
        )
        findings.append(
            Finding(
                id=_fid("nmap", action_id, f"{port}/{proto}"),
                title=f"Open port {port}/{proto} ({service})",
                affected_asset=target,
                source_tool="nmap",
                source_action_id=action_id,
                evidence=line,
                severity=severity,
                severity_rationale=rationale,
                # open = concrete scanner evidence; open|filtered is ambiguous.
                confidence="confirmed" if state == "open" else "hypothesis",
                reproducibility=f"nmap -p {port} {target}",
                remediation=(
                    f"Close or firewall {port}/{proto} if the {service} service is not "
                    "required; otherwise restrict access and keep it patched."
                ),
                references=[],
                audit_refs=list(audit_refs),
            )
        )
    return findings


def _nuclei_finding(
    *,
    tpl: str,
    name: str,
    sev: str,
    matched: str,
    evidence: str,
    extra: str,
    remediation: str,
    refs: list[str],
    action_id: str,
    target: str,
    audit_refs: list[str],
) -> Finding:
    severity = _NUCLEI_SEVERITIES[sev.lower()]
    references = list(refs)
    for cve in _CVE.findall(tpl):
        url = f"https://nvd.nist.gov/vuln/detail/{cve.upper()}"
        if url not in references:
            references.append(url)
    if not references:
        references = [f"nuclei-template:{tpl}"]
    repro = f"nuclei -u {matched} -id {tpl}"
    if extra:
        repro += f"  # extracted: {extra}"
    return Finding(
        id=_fid("nuclei", action_id, f"{tpl}|{matched}"),
        title=f"{name} ({tpl})" if name else tpl,
        affected_asset=target,
        source_tool="nuclei",
        source_action_id=action_id,
        evidence=evidence,
        severity=severity,
        severity_rationale=f"Severity '{sev.lower()}' as declared by nuclei template {tpl}.",
        confidence="confirmed",  # a template match is concrete tool evidence
        reproducibility=repro,
        remediation=remediation
        or f"Review the matched resource {matched} and apply the vendor fix for {tpl}.",
        references=references,
        audit_refs=list(audit_refs),
    )


def parse_nuclei(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for line in _clean(output):
        if line.startswith("{"):
            f = _parse_nuclei_json(line, action_id, target, audit_refs)
        else:
            f = _parse_nuclei_text(line, action_id, target, audit_refs)
        if f is not None:
            findings.append(f)
    return findings


def _parse_nuclei_text(
    line: str, action_id: str, target: str, audit_refs: list[str]
) -> Finding | None:
    m = _NUCLEI_TEXT.match(line)
    if not m or m["sev"].lower() not in _NUCLEI_SEVERITIES:
        return None
    return _nuclei_finding(
        tpl=m["tpl"],
        name="",
        sev=m["sev"],
        matched=m["matched"],
        evidence=line,
        extra=m["extra"] or "",
        remediation="",
        refs=[],
        action_id=action_id,
        target=target,
        audit_refs=audit_refs,
    )


def _parse_nuclei_json(
    line: str, action_id: str, target: str, audit_refs: list[str]
) -> Finding | None:
    try:
        d: Any = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(d, dict):
        return None
    info = d.get("info")
    tpl = d.get("template-id")
    if not isinstance(info, dict) or not isinstance(tpl, str):
        return None
    sev = str(info.get("severity", "")).lower()
    if sev not in _NUCLEI_SEVERITIES:
        return None
    refs = info.get("reference")
    extracted = d.get("extracted-results")
    return _nuclei_finding(
        tpl=tpl,
        name=str(info.get("name") or ""),
        sev=sev,
        matched=str(d.get("matched-at") or d.get("host") or target),
        evidence=line,
        extra=", ".join(map(str, extracted)) if isinstance(extracted, list) else "",
        remediation=str(info.get("remediation") or ""),
        refs=[str(r) for r in refs] if isinstance(refs, list) else [],
        action_id=action_id,
        target=target,
        audit_refs=audit_refs,
    )
