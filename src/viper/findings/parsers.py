"""Deterministic parsers: tool output -> list[Finding]. Pure functions, no I/O, no LLM.

Anything that does not match a strict line pattern is ignored, so prose (or injected
instructions) in tool output can never become a finding. Every record is parsed in
isolation (one hostile line cannot discard earlier findings) under fixed budgets, and every
tool-derived string is neutralised (escape sequences removed, control/bidi characters made
visible) before it reaches a Finding.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from urllib.parse import urlsplit

from viper.findings.models import Finding, Severity

# --- budgets (enforced here so direct/offline callers are bounded too) -------------------
MAX_INPUT_CHARS = 4 * 1024 * 1024
MAX_LINE_CHARS = 16 * 1024
MAX_LINES = 20_000
MAX_FINDINGS = 500
MAX_JSON_DEPTH = 32
MAX_TEMPLATE_ID = 128
MAX_LOCATION = 2048
MAX_REFERENCES = 20
MAX_REFERENCE_CHARS = 500
MAX_TEXT_FIELD = 1000

# --- neutralisation -----------------------------------------------------------------------
_ESC_SEQ = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC (hyperlinks, clipboard, title...)
    r"|\x9d[^\x07\x9c]*(?:\x07|\x9c)?"  # 8-bit OSC
    r"|\x1b\[[0-?]*[ -/]*[@-~]?"  # CSI
    r"|\x9b[0-?]*[ -/]*[@-~]?"  # 8-bit CSI
    r"|\x1b[P^_X][^\x1b]*(?:\x1b\\)?"  # DCS / PM / APC / SOS strings
    r"|\x1b[ -/]*[0-~]?"  # any other two-byte escape
)
_BIDI = frozenset(
    [0x061C, 0x200E, 0x200F]
    + list(range(0x202A, 0x202F))
    + list(range(0x2066, 0x206A))
)


def neutralise(text: str) -> str:
    """Drop terminal escape sequences; render remaining C0/C1/DEL and bidi controls visibly."""
    text = _ESC_SEQ.sub("", text)
    out: list[str] = []
    for ch in text:
        o = ord(ch)
        if ch == "\t":
            out.append(" ")
        elif o < 32 or 127 <= o <= 159:
            out.append(f"\\x{o:02x}")
        elif o in _BIDI:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    return "".join(out)


def _field(value: object, limit: int = MAX_TEXT_FIELD) -> str:
    return neutralise(str(value))[:limit]


# --- shared helpers -----------------------------------------------------------------------
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_TEMPLATE_ID = re.compile(rf"^[A-Za-z0-9][A-Za-z0-9_.:/\-]{{0,{MAX_TEMPLATE_ID - 1}}}$")
_LOCATION_SCHEMES = frozenset(
    {"http", "https", "tcp", "udp", "ssl", "tls", "ssh", "ftp", "ws", "wss", "dns"}
)


def _fid(tool: str, action_id: str, key: str) -> str:
    return "f-" + hashlib.sha256(f"{tool}|{action_id}|{key}".encode()).hexdigest()[:12]


def _lines(output: str) -> tuple[list[str], int]:
    """Neutralised, stripped, non-empty lines plus the number of lines dropped for budget."""
    skipped = 0
    if len(output) > MAX_INPUT_CHARS:
        output = output[:MAX_INPUT_CHARS]
        skipped += 1
    raw = output.splitlines()
    if len(raw) > MAX_LINES:
        skipped += len(raw) - MAX_LINES
        raw = raw[:MAX_LINES]
    lines: list[str] = []
    for ln in raw:
        if len(ln) > MAX_LINE_CHARS:
            skipped += 1
            continue
        clean = neutralise(ln).strip()
        if clean:
            lines.append(clean)
    return lines, skipped


def _host_of(location: str) -> str | None:
    """Lower-cased hostname of a match location (URL or host[:port]), or None if unusable."""
    if (
        not location
        or len(location) > MAX_LOCATION
        or any(c.isspace() or ord(c) < 32 or ord(c) >= 127 for c in location)
    ):
        return None
    try:
        parts = urlsplit(location if "://" in location else f"//{location}")
        _ = parts.port  # raises ValueError on a bad port
    except ValueError:
        return None
    if "://" in location and parts.scheme.lower() not in _LOCATION_SCHEMES:
        return None
    host = parts.hostname
    return host.lower() if host else None


def _target_host(target: str) -> str:
    return _host_of(target) or target.strip().lower()


def _json_depth_ok(s: str) -> bool:
    depth = 0
    in_str = esc = False
    for ch in s:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return False
        elif ch in "]}":
            depth -= 1
    return True


# --- nmap ---------------------------------------------------------------------------------
_NMAP_PORT = re.compile(
    r"^(?P<port>\d{1,5})/(?P<proto>tcp|udp|sctp)\s+(?P<state>open\|filtered|open)\s+"
    r"(?P<service>\S{1,64})(?:\s+(?P<version>.*))?$"
)
_NMAP_LOOSE = re.compile(r"^(?P<port>\d{1,10})/(?:tcp|udp|sctp)(?:\s+(?P<state>\S+))?")
_NMAP_STATES = frozenset(
    {"open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"}
)


def _nmap_row_is_garbled(line: str) -> bool:
    """A port-row-shaped line that should have parsed but is unusable.

    Normal rows (closed/filtered/unfiltered ports) are NOT garbled: they are healthy scan
    output that simply is not a finding.
    """
    m = _NMAP_LOOSE.match(line)
    if not m:
        return False
    state = m["state"]
    if state is None or state not in _NMAP_STATES or int(m["port"]) > 65535:
        return True
    return state in {"open", "open|filtered"}  # strict parse failed: e.g. no service column
# Services whose protocol sends credentials/data unencrypted.
_CLEARTEXT = {"telnet", "ftp", "rlogin", "rsh", "rexec", "tftp"}

_POSIX = "POSIX shell: "


def _nmap_record(line: str, action_id: str, target: str, audit_refs: list[str]) -> Finding | None:
    m = _NMAP_PORT.match(line)
    if not m or int(m["port"]) > 65535:
        return None
    port, proto, state, service = m["port"], m["proto"], m["state"], m["service"]
    cleartext = service.lower().rstrip("?") in _CLEARTEXT
    severity: Severity = "low" if cleartext else "info"
    rationale = (
        f"{service} transmits data unencrypted; exposure of an open port raises risk."
        if cleartext
        else "An open port is attack surface, not by itself a vulnerability."
    )
    return Finding(
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
        reproducibility=_POSIX + f"nmap -p {port} {shlex.quote(target)}",
        remediation=(
            f"Close or firewall {port}/{proto} if the {service} service is not "
            "required; otherwise restrict access and keep it patched."
        ),
        references=[],
        audit_refs=list(audit_refs),
    )


def parse_nmap_ex(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> tuple[list[Finding], int]:
    lines, skipped = _lines(output)
    findings: list[Finding] = []
    seen: set[str] = set()
    for line in lines:
        if len(findings) >= MAX_FINDINGS:
            skipped += 1
            continue
        try:
            f = _nmap_record(line, action_id, target, audit_refs)
        except Exception:  # noqa: BLE001 - isolate any malformed record
            f = None
        if f is None:
            if _nmap_row_is_garbled(line):
                skipped += 1
            continue
        if f.id not in seen:
            seen.add(f.id)
            findings.append(f)
    return findings, skipped


def parse_nmap(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> list[Finding]:
    return parse_nmap_ex(output, action_id=action_id, target=target, audit_refs=audit_refs)[0]


# --- nuclei -------------------------------------------------------------------------------
_NUCLEI_TEXT = re.compile(
    r"^(?:\[\d{4}-\d\d-\d\d[^\]]*\]\s+)?"  # optional timestamp prefix
    r"\[(?P<tpl>[^\]]+)\]\s+\[(?P<proto>[^\]]+)\]\s+\[(?P<sev>[^\]]+)\]\s+"
    r"(?P<matched>\S+)(?:\s+(?P<extra>.*))?$"
)
_NUCLEI_LOOSE = re.compile(r"^(?:\[\d{4}-\d\d-\d\d[^\]]*\]\s+)?\[[^\]]+\]\s+\[[^\]]+\]\s+\[")
_NUCLEI_SEVERITIES: dict[str, Severity] = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "info",
}


def _nuclei_finding(
    *,
    tpl: str,
    name: str,
    sev: str,
    matched: str,
    evidence: str,
    remediation: str,
    refs: list[str],
    action_id: str,
    target: str,
    audit_refs: list[str],
    description: str = "",
    cwe: list[str] | None = None,
) -> Finding | None:
    """Build a finding from validated-shape inputs, or None if the record is unusable."""
    if not _TEMPLATE_ID.match(tpl) or sev.lower() not in _NUCLEI_SEVERITIES:
        return None
    host = _host_of(matched)
    if host is None:  # no usable match location -> not evidence of anything
        return None
    severity = _NUCLEI_SEVERITIES[sev.lower()]

    references: list[str] = []
    seen_refs: set[str] = set()

    def add_ref(ref: str) -> None:
        if ref and ref not in seen_refs and len(references) < MAX_REFERENCES:
            seen_refs.add(ref)
            references.append(ref)

    for r in refs:
        add_ref(_field(r, MAX_REFERENCE_CHARS))
    for cve in _CVE.findall(tpl):
        add_ref(f"https://nvd.nist.gov/vuln/detail/{cve.upper()}")
    if not references:
        references = [f"nuclei-template:{tpl}"]

    title = f"{_field(name, 200)} ({tpl})" if name else tpl
    repro = (
        _POSIX + f"nuclei -u {shlex.quote(matched)} -id {shlex.quote(tpl)}"
    )
    confidence = "confirmed"  # a template match on the approved host is concrete evidence
    rationale = f"Severity '{sev.lower()}' as declared by nuclei template {tpl}."
    asset = target
    if host != _target_host(target):
        # Matched somewhere other than the approved target (redirect, CDN, third party):
        # never a confirmed finding on the approved asset.
        confidence = "hypothesis"
        severity = "info"
        title = f"Foreign-host observation: {title}"
        rationale = (
            f"Template {tpl} matched host {_field(host, 255)}, which differs from the approved "
            f"target; recorded as an unconfirmed observation (declared severity '{sev.lower()}')."
        )
    return Finding(
        id=_fid("nuclei", action_id, f"{tpl}|{matched}"),
        title=title,
        affected_asset=asset,
        source_tool="nuclei",
        source_action_id=action_id,
        evidence=evidence,
        severity=severity,
        severity_rationale=rationale,
        confidence=confidence,  # type: ignore[arg-type]
        reproducibility=repro,
        remediation=remediation
        or f"Review the matched resource and apply the vendor fix for {tpl}.",
        references=references,
        audit_refs=list(audit_refs),
        description=description,
        cwe=list(cwe or []),
    )


def _nuclei_text(line: str, action_id: str, target: str, audit_refs: list[str]) -> Finding | None:
    m = _NUCLEI_TEXT.match(line)
    if not m:
        return None
    return _nuclei_finding(
        tpl=m["tpl"],
        name="",
        sev=m["sev"],
        matched=m["matched"],
        evidence=line,
        remediation="",
        refs=[],
        action_id=action_id,
        target=target,
        audit_refs=audit_refs,
    )


class _NotAMatch(Exception):  # noqa: N818 - control-flow marker, not an error
    """A well-formed record that nuclei itself says did not match (not counted as skipped)."""


_CWE_ID = re.compile(r"(?i)cwe-(\d{1,5})")
MAX_CWE = 10


def _nuclei_cwe(info: dict[str, object]) -> list[str]:
    """CWE ids from ``info.classification.cwe-id`` (string or list); malformed values dropped."""
    classification = info.get("classification")
    raw = classification.get("cwe-id") if isinstance(classification, dict) else None
    values = raw if isinstance(raw, list) else [raw]
    out: list[str] = []
    for v in values[:MAX_CWE * 2]:
        m = _CWE_ID.fullmatch(v.strip()) if isinstance(v, str) else None
        if m and f"CWE-{int(m[1])}" not in out and len(out) < MAX_CWE:
            out.append(f"CWE-{int(m[1])}")
    return out


def _nuclei_json(line: str, action_id: str, target: str, audit_refs: list[str]) -> Finding | None:
    if not _json_depth_ok(line):
        return None
    d = json.loads(line)
    if not isinstance(d, dict):
        return None
    info = d.get("info")
    tpl = d.get("template-id")
    if not isinstance(info, dict) or not isinstance(tpl, str):
        return None
    status = d.get("matcher-status")
    if status is False or (isinstance(status, str) and status.strip().lower() == "false"):
        raise _NotAMatch  # nuclei explicitly reports no match: normal, not malformed
    location = d.get("matched-at") or d.get("host")
    if not isinstance(location, str):
        return None
    sev = info.get("severity")
    if not isinstance(sev, str):
        return None
    refs = info.get("reference")
    ref_list = [r for r in refs[:MAX_REFERENCES] if isinstance(r, str)] if isinstance(refs, list) else []
    return _nuclei_finding(
        tpl=tpl,
        name=str(info.get("name") or "") if isinstance(info.get("name"), (str, type(None))) else "",
        sev=sev,
        matched=location,
        evidence=line,
        remediation=_field(info["remediation"]) if isinstance(info.get("remediation"), str) else "",
        refs=ref_list,
        action_id=action_id,
        target=target,
        audit_refs=audit_refs,
        description=_field(info["description"]) if isinstance(info.get("description"), str) else "",
        cwe=_nuclei_cwe(info),
    )


def parse_nuclei_ex(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> tuple[list[Finding], int]:
    lines, skipped = _lines(output)
    findings: list[Finding] = []
    seen: set[str] = set()
    for line in lines:
        is_json = line.startswith("{")
        if not is_json and not _NUCLEI_LOOSE.match(line):
            continue  # prose/noise, not a record
        if len(findings) >= MAX_FINDINGS:
            skipped += 1
            continue
        try:
            parser = _nuclei_json if is_json else _nuclei_text
            f = parser(line, action_id, target, audit_refs)
        except _NotAMatch:
            continue
        except Exception:  # noqa: BLE001 - JSONDecodeError, RecursionError, bad types...
            f = None
        if f is None:
            skipped += 1
            continue
        if f.id not in seen:
            seen.add(f.id)
            findings.append(f)
    return findings, skipped


def parse_nuclei(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> list[Finding]:
    return parse_nuclei_ex(output, action_id=action_id, target=target, audit_refs=audit_refs)[0]
