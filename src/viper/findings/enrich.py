"""Deterministic finding enrichment (F1): fill gaps from a curated table, never overwrite specifics.

Pure and offline. ``enrich`` only ever touches ``description``, ``cwe``, ``references`` and a
GENERIC ``remediation`` (the placeholder text the parsers emit when the tool gave none).
Anything the parser took from the tool's own structured output wins, and severity, confidence,
evidence, titles and audit references are never changed. Unknown template ids or services pass
through unchanged. The table is keyed by the finding's ``source_tool`` so text controlled by one
tool's output cannot select another tool's entry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from viper.findings.models import Finding

# Placeholder remediation texts emitted by viper.findings.parsers (a test pins them together).
GENERIC_REMEDIATION_PREFIXES: tuple[str, ...] = (
    "Close or firewall ",
    "Review the matched resource and apply the vendor fix for ",
)
_PLACEHOLDER_REF = "nuclei-template:"
MAX_REFERENCES = 20


@dataclass(frozen=True)
class Entry:
    description: str
    remediation: str
    cwe: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


_OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
_RFC = "https://www.rfc-editor.org/rfc/"

NUCLEI_TABLE: dict[str, Entry] = {
    "http-missing-security-headers": Entry(
        "The response lacks one or more recommended HTTP security headers (for example "
        "Content-Security-Policy, X-Frame-Options, Strict-Transport-Security), which weakens "
        "browser-side protections against clickjacking, content injection and downgrade attacks.",
        "Send the recommended security headers on all responses (CSP, X-Frame-Options or "
        "frame-ancestors, X-Content-Type-Options, Referrer-Policy, and HSTS over HTTPS).",
        ("CWE-693",), (_OWASP_HEADERS,)),
    "tech-detect": Entry(
        "The server reveals the technologies it runs (frameworks, libraries, servers), which "
        "helps an attacker choose version-specific attacks. Informational on its own.",
        "Remove or minimise technology and version disclosure in headers and pages where "
        "practical, and keep every detected component patched.",
        ("CWE-200",), ("https://owasp.org/www-project-web-security-testing-guide/",)),
    "waf-detect": Entry(
        "A web application firewall or similar protective layer was detected in front of the "
        "target. Informational: it affects how reliable scan results are.",
        "No fix needed. Do not rely on the WAF as the only control; fix application "
        "weaknesses at the source.",
        (), ("https://owasp.org/www-community/Web_Application_Firewall",)),
    "apache-detect": Entry(
        "The Apache HTTP Server version is disclosed in the Server header, which helps an "
        "attacker match known vulnerabilities to the exact version.",
        "Reduce version disclosure (ServerTokens Prod, ServerSignature Off) and keep Apache "
        "updated to a supported release.",
        ("CWE-200",), ("https://httpd.apache.org/docs/current/mod/core.html#servertokens",)),
    "nginx-version": Entry(
        "The nginx version is disclosed in the Server header, which helps an attacker match "
        "known vulnerabilities to the exact version.",
        "Set server_tokens off and keep nginx updated to a supported release.",
        ("CWE-200",), ("https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens",)),
    "nginx-eol": Entry(
        "The detected nginx version is end-of-life and no longer receives security fixes.",
        "Upgrade nginx to a currently supported release.",
        ("CWE-1104",), ("https://nginx.org/en/CHANGES",)),
    "robots-txt": Entry(
        "A robots.txt file is present. It can list paths the owner would rather not have "
        "indexed, which sometimes points at sensitive areas.",
        "Do not rely on robots.txt to hide anything; protect sensitive paths with "
        "authentication and avoid listing them.",
        ("CWE-200",), ("https://www.rfc-editor.org/rfc/rfc9309",)),
    "robots-txt-endpoint": Entry(
        "A robots.txt file is present. It can list paths the owner would rather not have "
        "indexed, which sometimes points at sensitive areas.",
        "Do not rely on robots.txt to hide anything; protect sensitive paths with "
        "authentication and avoid listing them.",
        ("CWE-200",), ("https://www.rfc-editor.org/rfc/rfc9309",)),
    "git-config": Entry(
        "A .git/config file is publicly readable, which can disclose repository locations, "
        "and often enables recovery of source code.",
        "Block web access to the .git directory and remove it from deployed content.",
        ("CWE-538",), ("https://owasp.org/www-project-web-security-testing-guide/",)),
    "ds-store-file": Entry(
        "A macOS .DS_Store file is exposed and can disclose directory and file names.",
        "Delete .DS_Store files from deployed content and block access to dotfiles.",
        ("CWE-538",), ()),
    "phpinfo-files": Entry(
        "A phpinfo() page is exposed and discloses configuration, paths and loaded modules.",
        "Remove phpinfo pages from production and restrict diagnostic endpoints.",
        ("CWE-200",), ("https://www.php.net/manual/en/function.phpinfo.php",)),
    "security-txt": Entry(
        "A security.txt file is present. This is a positive practice: it tells researchers "
        "how to report vulnerabilities.",
        "No fix needed. Keep the contact details and expiry date current.",
        (), (_RFC + "rfc9116",)),
    "exposed-panels": Entry(
        "An administrative or management interface is reachable, widening the attack surface "
        "for credential guessing and known panel vulnerabilities.",
        "Restrict management interfaces to trusted networks or a VPN and require strong "
        "authentication.",
        ("CWE-284",), ("https://owasp.org/www-project-top-ten/",)),
}

_CLEARTEXT_REMEDIATION = (
    "Replace the cleartext service with an encrypted equivalent (for example SSH or SFTP), "
    "or restrict it to a trusted network; close the port if it is not required."
)

NMAP_SERVICE_TABLE: dict[str, Entry] = {
    "ssh": Entry(
        "SSH provides encrypted remote login. An exposed SSH port invites credential guessing "
        "and attacks on outdated servers.",
        "Restrict SSH to trusted addresses, require key-based authentication, disable root "
        "and password login, and keep OpenSSH patched.",
        (), (_RFC + "rfc4253",)),
    "http": Entry(
        "An unencrypted web service is reachable. Traffic can be read or altered in transit "
        "and the application is exposed to web attacks.",
        "Redirect HTTP to HTTPS, keep the web server and application patched, and expose "
        "only what is required.",
        (), (_RFC + "rfc9110",)),
    "https": Entry(
        "An encrypted web service is reachable. The application is exposed to web attacks "
        "and its TLS configuration should be reviewed.",
        "Keep the web server and application patched, use modern TLS settings and valid "
        "certificates, and expose only what is required.",
        (), (_RFC + "rfc9110",)),
    "ftp": Entry(
        "FTP transmits credentials and data unencrypted and is a frequent target of "
        "credential attacks.",
        _CLEARTEXT_REMEDIATION, ("CWE-319",), (_RFC + "rfc959",)),
    "telnet": Entry(
        "Telnet transmits credentials and data unencrypted and gives remote shell access.",
        _CLEARTEXT_REMEDIATION, ("CWE-319",), (_RFC + "rfc854",)),
    "smtp": Entry(
        "An SMTP mail server is reachable. Misconfiguration can allow relay abuse or user "
        "enumeration.",
        "Disable open relay, require authentication and TLS for submission, and restrict "
        "access where mail is not needed.",
        (), (_RFC + "rfc5321",)),
    "ms-wbt-server": Entry(
        "Remote Desktop (RDP) is reachable. Exposed RDP is a common target of credential "
        "attacks and has had serious vulnerabilities.",
        "Do not expose RDP to untrusted networks; use a VPN or gateway, enforce network "
        "level authentication and MFA, and keep Windows patched.",
        (), ("https://learn.microsoft.com/windows-server/remote/remote-desktop-services/welcome-to-rds",)),
    "mysql": Entry(
        "A MySQL database port is reachable. Databases should not be exposed to untrusted "
        "networks.",
        "Bind the database to localhost or a private network, require strong authentication, "
        "and firewall the port.",
        (), ("https://dev.mysql.com/doc/refman/8.0/en/security.html",)),
    "postgresql": Entry(
        "A PostgreSQL database port is reachable. Databases should not be exposed to "
        "untrusted networks.",
        "Bind the database to localhost or a private network, restrict pg_hba.conf, and "
        "firewall the port.",
        (), ("https://www.postgresql.org/docs/current/auth-pg-hba-conf.html",)),
    "microsoft-ds": Entry(
        "SMB file sharing is reachable. Exposed SMB has been abused for worms and "
        "credential relay.",
        "Block SMB at the network edge, disable SMBv1, and require signing and "
        "authentication.",
        (), ("https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",)),
    "domain": Entry(
        "A DNS service is reachable. Open resolvers and zone transfers can be abused.",
        "Disable recursion for untrusted clients, restrict zone transfers, and keep the "
        "DNS software patched.",
        (), (_RFC + "rfc1034",)),
    "vnc": Entry(
        "VNC remote desktop is reachable and is often weakly authenticated or unencrypted.",
        "Do not expose VNC; tunnel it through SSH or a VPN and require strong authentication.",
        ("CWE-319",), ()),
}

_NUCLEI_ID = re.compile(r"\(([A-Za-z0-9][A-Za-z0-9_.:/\-]{0,127})\)\s*$")
_NMAP_SERVICE = re.compile(r"^Open port \d{1,5}/(?:tcp|udp|sctp) \(([^()\s]{1,64})\)$")


def _entry_for(finding: Finding) -> Entry | None:
    if finding.source_tool == "nuclei":
        m = _NUCLEI_ID.search(finding.title)
        return NUCLEI_TABLE.get(m[1].lower()) if m else None
    m = _NMAP_SERVICE.match(finding.title)
    return NMAP_SERVICE_TABLE.get(m[1].lower().rstrip("?")) if m else None


def _is_generic(remediation: str) -> bool:
    return not remediation.strip() or remediation.startswith(GENERIC_REMEDIATION_PREFIXES)


def _has_specific_references(references: list[str]) -> bool:
    return any(not r.startswith(_PLACEHOLDER_REF) for r in references)


def enrich(finding: Finding) -> Finding:
    """Return a copy with curated description / CWE / references / remediation filled in."""
    entry = _entry_for(finding)
    if entry is None:
        return finding
    update: dict[str, object] = {}
    if not finding.description:
        update["description"] = entry.description
    if not finding.cwe and entry.cwe:
        update["cwe"] = list(entry.cwe)
    if _is_generic(finding.remediation):
        update["remediation"] = entry.remediation
    if not _has_specific_references(finding.references) and entry.references:
        update["references"] = list(entry.references)[:MAX_REFERENCES]
    if not update:
        return finding
    return Finding.model_validate({**finding.model_dump(), **update})
