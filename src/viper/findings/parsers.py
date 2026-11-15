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
from typing import Any
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


_RE_REQUESTS = re.compile(
    r"(?:(?:\|\s*)?Requests:\s*(\d+)|\b(?:requests?|reqs?)\s*[:=]\s*(\d+)\b)",
    re.IGNORECASE,
)
_RE_TEMPLATES = re.compile(
    r"(?:(?:\|\s*)?Templates:\s*(\d+)|\b(?:templates?|tpls?)\s*[:=]\s*(\d+)\b)",
    re.IGNORECASE,
)


def parse_nuclei_metrics(output: str) -> dict[str, int | None]:
    """Extract per-run scanner metrics: executed template count and request count.

    Parses explicit stats records or counts executed template IDs from output lines.
    Returns integer counts when present, or None if missing (never defaults to 0).
    """
    if not output:
        return {"template_count": None, "request_count": None}
    lines, _ = _lines(output)
    stat_templates: int | None = None
    stat_requests: int | None = None
    seen_templates: set[str] = set()

    for line in lines:
        if line.startswith("{"):
            if not _json_depth_ok(line):
                continue
            try:
                d = json.loads(line)
            except Exception:  # noqa: BLE001, S112
                continue
            if not isinstance(d, dict):
                continue

            for key in ("requests", "request_count", "reqs"):
                val = d.get(key)
                if isinstance(val, int) and not isinstance(val, bool) and val >= 0:
                    stat_requests = val
                    break
                if isinstance(val, str) and val.isdigit():
                    stat_requests = int(val)
                    break

            for key in ("templates", "template_count", "executed_templates", "tpls"):
                val = d.get(key)
                if isinstance(val, int) and not isinstance(val, bool) and val >= 0:
                    stat_templates = val
                    break
                if isinstance(val, str) and val.isdigit():
                    stat_templates = int(val)
                    break

            tpl = d.get("template-id")
            if isinstance(tpl, str) and _TEMPLATE_ID.match(tpl):
                seen_templates.add(tpl)
        else:
            m_req = _RE_REQUESTS.search(line)
            if m_req:
                val_str = m_req.group(1) or m_req.group(2)
                if val_str and val_str.isdigit():
                    stat_requests = int(val_str)

            m_tpl = _RE_TEMPLATES.search(line)
            if m_tpl:
                val_str = m_tpl.group(1) or m_tpl.group(2)
                if val_str and val_str.isdigit():
                    stat_templates = int(val_str)

            m_rec = _NUCLEI_TEXT.match(line)
            if m_rec:
                tpl = m_rec["tpl"]
                if _TEMPLATE_ID.match(tpl):
                    seen_templates.add(tpl)

    final_templates = (
        stat_templates
        if stat_templates is not None
        else (len(seen_templates) if seen_templates else None)
    )
    final_requests = stat_requests
    return {"template_count": final_templates, "request_count": final_requests}


# --- v1.2 web-app probes (otp_2fa_probe, upload_bypass_probe, injection_probe) -------------
# One JSON object per line (the probes' own JSONL contract, mirroring nuclei's -jsonl). Every
# record is independently re-validated here: malformed/garbled lines are skipped, never trusted,
# so a hostile or buggy probe line can never fabricate a "confirmed" finding.

def _probe_records(output: str) -> tuple[list[dict[str, Any]], int]:
    lines, skipped = _lines(output)
    records: list[dict[str, Any]] = []
    for line in lines[:MAX_LINES]:
        if not line.startswith("{") or not _json_depth_ok(line):
            skipped += 1
            continue
        try:
            d = json.loads(line)
        except Exception:  # noqa: BLE001, S112
            skipped += 1
            continue
        if isinstance(d, dict):
            records.append(d)
        else:
            skipped += 1
    return records, skipped


def parse_otp_probe(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> list[Finding]:
    findings, _ = parse_otp_probe_ex(output, action_id=action_id, target=target, audit_refs=audit_refs)
    return findings


def parse_otp_probe_ex(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> tuple[list[Finding], int]:
    """One finding per run at most: the probe's own records decide whether the OTP endpoint's
    rate limit/lockout held (no finding) or did not (confirmed), or whether an enumerate_codes
    run ever got a 2xx (confirmed, critical: the code was accepted).
    """
    all_records, skipped = _probe_records(output)
    mine = [r for r in all_records if r.get("tool") == "otp_2fa_probe"]
    records = [r for r in mine if isinstance(r.get("mode"), str) and isinstance(r.get("status_code"), int)]
    skipped += len(mine) - len(records)
    if not records:
        return [], skipped
    mode = records[0].get("mode")
    endpoint = _field(records[0].get("endpoint_path", ""), MAX_LOCATION)
    evidence = _field(output, MAX_TEXT_FIELD * 4)
    if mode == "enumerate_codes":
        hit = next((r for r in records if isinstance(r.get("status_code"), int)
                   and 200 <= r["status_code"] < 300), None)
        if hit is None:
            return [], skipped
        return [Finding(
            id=_fid("otp_2fa_probe", action_id, "enumerate_codes-accepted"),
            title=f"OTP code accepted during bounded enumeration on {endpoint}",
            affected_asset=target, source_tool="otp_2fa_probe", source_action_id=action_id,
            evidence=evidence, severity="critical",
            severity_rationale="A bounded OTP-code guess was accepted (2xx) during a scope-"
                               "permitted enumeration probe.",
            confidence="confirmed", reproducibility="Replay the same bounded guesses against "
                                                     f"{endpoint} with the probe's recorded attempts.",
            remediation="Enforce per-account OTP attempt limits and lockout independent of source IP.",
            references=[], audit_refs=list(audit_refs),
        )], skipped
    if mode == "rate_limit_probe":
        if any(r.get("lockout_observed") is True for r in records):
            return [], skipped  # the limit held: not a finding
        return [Finding(
            id=_fid("otp_2fa_probe", action_id, "rate-limit-probe-no-lockout"),
            title=f"No OTP rate limit/lockout observed on {endpoint}",
            affected_asset=target, source_tool="otp_2fa_probe", source_action_id=action_id,
            evidence=evidence, severity="high",
            severity_rationale=f"{len(records)} bounded wrong-code attempts produced no lockout "
                               "or throttling signal (429/423/explicit 403 lockout message).",
            confidence="confirmed",
            reproducibility=f"Repeat {len(records)} wrong-code attempts against {endpoint}.",
            remediation="Add a per-account/IP OTP attempt counter with lockout or backoff.",
            references=[], audit_refs=list(audit_refs),
        )], skipped
    return [], skipped


def parse_upload_probe(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> list[Finding]:
    findings, _ = parse_upload_probe_ex(output, action_id=action_id, target=target, audit_refs=audit_refs)
    return findings


def parse_upload_probe_ex(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> tuple[list[Finding], int]:
    """Confirmed when the probe's own fixed, benign file was accepted (2xx) — an unambiguous
    accept/reject signal from the server, never inferred from prose.
    """
    all_records, skipped = _probe_records(output)
    records = [r for r in all_records if r.get("tool") == "upload_bypass_probe"]
    findings: list[Finding] = []
    seen: set[str] = set()
    for r in records:
        status = r.get("status_code")
        variant = r.get("variant")
        if not isinstance(status, int) or not isinstance(variant, str):
            skipped += 1
            continue
        if not (200 <= status < 300):
            continue  # a clean reject (not 2xx) is a normal outcome, not a malformed record
        endpoint = _field(r.get("endpoint_path", ""), MAX_LOCATION)
        key = f"{variant}|{endpoint}"
        if key in seen or len(findings) >= MAX_FINDINGS:
            continue
        seen.add(key)
        label = {"content_detector_marker": "content-detector bypass",
                 "disallowed_extension_render": "extension allow-list bypass"}.get(variant, variant)
        findings.append(Finding(
            id=_fid("upload_bypass_probe", action_id, key),
            title=f"Upload {label} accepted on {endpoint}",
            affected_asset=target, source_tool="upload_bypass_probe", source_action_id=action_id,
            evidence=_field(json.dumps(r), MAX_TEXT_FIELD * 2),
            severity="critical",
            severity_rationale=f"Server returned {status} for a fixed, reviewed {variant} probe "
                               "file that should have been rejected by the upload filter.",
            confidence="confirmed",
            reproducibility=f"Re-upload the same fixed {variant} probe file to {endpoint}.",
            remediation="Validate uploaded content server-side (magic bytes, re-encode images, "
                        "reject by allow-listed MIME+extension pair), not by extension alone.",
            references=[], audit_refs=list(audit_refs),
        ))
    return findings, skipped


_INJECTION_SEVERITY: dict[str, Severity] = {
    "xss_reflected_marker": "high",
    "command_injection_marker": "critical",
    "url_injection_redirect": "medium",
}
_INJECTION_SIGNAL_FIELD = {
    "xss_reflected_marker": "marker_reflected_unescaped",
    "command_injection_marker": "marker_echoed",
    "url_injection_redirect": "redirected_to_payload",
}


def parse_injection_probe(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> list[Finding]:
    findings, _ = parse_injection_probe_ex(output, action_id=action_id, target=target, audit_refs=audit_refs)
    return findings


def parse_injection_probe_ex(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> tuple[list[Finding], int]:
    """XSS/command-injection/redirect: confirmed only when the probe's own explicit boolean
    signal is True. SQLi (boolean-diff/timing) needs a baseline comparison this single-shot
    probe does not take, so it is always reported as an unconfirmed hypothesis for a human to
    verify with a second request, never silently promoted to confirmed.
    """
    all_records, skipped = _probe_records(output)
    records = [r for r in all_records if r.get("tool") == "injection_probe"]
    findings: list[Finding] = []
    seen: set[str] = set()
    for r in records:
        technique = r.get("technique")
        endpoint = r.get("endpoint_path")
        param = r.get("param_name")
        if not isinstance(technique, str) or not isinstance(endpoint, str) or not isinstance(param, str):
            skipped += 1
            continue
        endpoint = _field(endpoint, MAX_LOCATION)
        param = _field(param, 64)
        key = f"{technique}|{endpoint}|{param}"
        if key in seen or len(findings) >= MAX_FINDINGS:
            continue
        evidence = _field(json.dumps(r), MAX_TEXT_FIELD * 2)
        if technique in _INJECTION_SIGNAL_FIELD:
            if r.get(_INJECTION_SIGNAL_FIELD[technique]) is not True:
                continue
            seen.add(key)
            findings.append(Finding(
                id=_fid("injection_probe", action_id, key),
                title=f"{technique.replace('_', ' ')} confirmed on {endpoint} ({param})",
                affected_asset=target, source_tool="injection_probe", source_action_id=action_id,
                evidence=evidence, severity=_INJECTION_SEVERITY.get(technique, "medium"),
                severity_rationale=f"Probe's own {_INJECTION_SIGNAL_FIELD[technique]} signal "
                                   "was True: the fixed, reviewed marker was observed unescaped "
                                   "in the response.",
                confidence="confirmed",
                reproducibility=f"Resend the same fixed {technique} probe payload to {param} on "
                                f"{endpoint}.",
                remediation="Encode/escape output and validate input server-side for this "
                            "parameter; parameterize any underlying query.",
                references=[], audit_refs=list(audit_refs),
            ))
        elif technique in ("sqli_boolean", "sqli_time"):
            seen.add(key)
            findings.append(Finding(
                id=_fid("injection_probe", action_id, key),
                title=f"Possible {technique.replace('_', ' ')} on {endpoint} ({param})",
                affected_asset=target, source_tool="injection_probe", source_action_id=action_id,
                evidence=evidence, severity="info",
                severity_rationale="Single-shot probe has no baseline response/timing to diff "
                                   "against; this is an unconfirmed hypothesis only.",
                confidence="hypothesis",
                reproducibility=f"Manually compare this response/timing against a baseline "
                                f"request to {endpoint} without the {technique} payload.",
                remediation="Use parameterized queries; verify manually with a baseline "
                            "comparison before treating this as a confirmed finding.",
                references=[], audit_refs=list(audit_refs),
            ))
    return findings, skipped


_SECRET_SEVERITY: dict[str, Severity] = {
    "aws_access_key": "high", "bearer_token": "high", "jwt": "high",
    "internal_hostname": "medium",
}


def parse_secret_scan(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> list[Finding]:
    return parse_secret_scan_ex(output, action_id=action_id, target=target, audit_refs=audit_refs)[0]


def parse_secret_scan_ex(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> tuple[list[Finding], int]:
    """One confirmed finding per fixed pattern/path; retain only the probe's redacted snippet."""
    records, skipped = _probe_records(output)
    findings: list[Finding] = []
    seen: set[str] = set()
    for record in records:
        if record.get("tool") != "secret_scan":
            continue
        path, matches = record.get("path"), record.get("matches")
        if not isinstance(path, str) or not isinstance(matches, list):
            skipped += 1
            continue
        for match in matches:
            if not isinstance(match, dict):
                skipped += 1
                continue
            pattern, snippet = match.get("pattern_name"), match.get("redacted_snippet")
            if (not isinstance(pattern, str) or pattern not in _SECRET_SEVERITY
                    or not isinstance(snippet, str)):
                skipped += 1
                continue
            key = f"{pattern}|{path}"
            if key in seen:
                continue
            if len(findings) >= MAX_FINDINGS:
                skipped += 1
                continue
            seen.add(key)
            endpoint = _field(path, MAX_LOCATION)
            findings.append(Finding(
                id=_fid("secret_scan", action_id, key),
                title=f"Exposed {pattern.replace('_', ' ')} in {endpoint}",
                affected_asset=target, source_tool="secret_scan", source_action_id=action_id,
                evidence=_field(snippet), severity=_SECRET_SEVERITY[pattern],
                severity_rationale="The public response matched the probe's fixed "
                                   f"{pattern} pattern.",
                confidence="confirmed",
                reproducibility=f"Fetch {endpoint} and run the same fixed secret scan.",
                remediation="Remove exposed secrets or internal hostnames from public assets; "
                            "revoke and rotate exposed credentials.",
                references=[], audit_refs=list(audit_refs),
            ))
    return findings, skipped


def parse_graphql_introspect(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> list[Finding]:
    return parse_graphql_introspect_ex(
        output, action_id=action_id, target=target, audit_refs=audit_refs)[0]


def parse_graphql_introspect_ex(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> tuple[list[Finding], int]:
    """Schema disclosure is confirmed only by the probe's explicit true boolean signal."""
    records, skipped = _probe_records(output)
    findings: list[Finding] = []
    seen: set[str] = set()
    for record in records:
        if record.get("tool") != "graphql_introspect":
            continue
        path, enabled = record.get("path"), record.get("introspection_enabled")
        if not isinstance(path, str) or type(enabled) is not bool:
            skipped += 1
            continue
        if enabled is not True or path in seen:
            continue
        if len(findings) >= MAX_FINDINGS:
            skipped += 1
            continue
        seen.add(path)
        endpoint = _field(path, MAX_LOCATION)
        findings.append(Finding(
            id=_fid("graphql_introspect", action_id, path),
            title=f"GraphQL schema disclosed through introspection on {endpoint}",
            affected_asset=target, source_tool="graphql_introspect", source_action_id=action_id,
            evidence=_field(json.dumps(record), MAX_TEXT_FIELD * 2), severity="medium",
            severity_rationale="The fixed introspection query returned schema information.",
            confidence="confirmed",
            reproducibility=f"Send the same fixed introspection query to {endpoint}.",
            remediation="Disable public introspection or restrict it to authorized users.",
            references=[], audit_refs=list(audit_refs),
        ))
    return findings, skipped


# ---------------------------------------------------------------------------- zap_baseline
_ZAP_RISK_TO_SEVERITY: dict[str, str] = {
    "informational": "info", "info": "info", "low": "low",
    "medium": "medium", "high": "high", "critical": "critical",
}
# ZAP's own confidence: only its strongest levels earn a "confirmed" finding; the rest stay
# hypotheses, consistent with the project rule that confirmed needs deterministic evidence.
_ZAP_CONFIRMED = frozenset({"high", "confirmed"})


def parse_zap_probe(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> list[Finding]:
    return parse_zap_probe_ex(output, action_id=action_id, target=target, audit_refs=audit_refs)[0]


def parse_zap_probe_ex(
    output: str, *, action_id: str, target: str, audit_refs: list[str]
) -> tuple[list[Finding], int]:
    """Parse OWASP ZAP baseline JSONL alerts (spider + passive rules) into Findings.

    Each record is one ZAP alert; severity comes from ZAP's risk, confidence from ZAP's own
    confidence rating. Malformed records are skip-counted, never silently dropped.
    """
    records, skipped = _probe_records(output)
    findings: list[Finding] = []
    seen: set[str] = set()
    for record in records:
        if record.get("tool") != "zap_baseline":
            continue
        alert = record.get("alert")
        url = record.get("url")
        risk = str(record.get("risk", "")).strip().lower()
        if not isinstance(alert, str) or not alert or not isinstance(url, str) or not url:
            skipped += 1
            continue
        severity = _ZAP_RISK_TO_SEVERITY.get(risk)
        if severity is None:
            skipped += 1
            continue
        key = f"{alert}|{url}"
        if key in seen:
            continue
        if len(findings) >= MAX_FINDINGS:
            skipped += 1
            continue
        seen.add(key)
        conf = str(record.get("confidence", "")).strip().lower()
        confidence = "confirmed" if conf in _ZAP_CONFIRMED else "hypothesis"
        cwe: list[str] = []
        raw_cwe = str(record.get("cweid", "")).strip()
        if raw_cwe.isdigit() and int(raw_cwe) > 0:
            cwe = [f"CWE-{int(raw_cwe)}"]
        location = _field(url, MAX_LOCATION)
        refs = [r for r in [_field(str(record.get("reference", "")), MAX_REFERENCE_CHARS)] if r]
        findings.append(Finding(
            id=_fid("zap_baseline", action_id, key),
            title=_field(f"{alert} at {location}", MAX_TEXT_FIELD),
            affected_asset=target, source_tool="zap_baseline", source_action_id=action_id,
            evidence=_field(json.dumps(record), MAX_TEXT_FIELD * 2),
            severity=severity,  # type: ignore[arg-type]
            severity_rationale=f"ZAP reported this alert at {risk or 'unknown'} risk.",
            confidence=confidence,  # type: ignore[arg-type]
            reproducibility=f"Re-run a ZAP baseline (spider + passive) scan against {location}.",
            remediation=_field(str(record.get("solution", "")) or "See the ZAP alert reference.",
                               MAX_TEXT_FIELD),
            description=_field(str(record.get("description", "")), MAX_TEXT_FIELD),
            references=refs, audit_refs=list(audit_refs), cwe=cwe,
        ))
    return findings, skipped
