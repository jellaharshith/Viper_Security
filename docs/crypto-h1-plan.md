# Crypto.com HackerOne Engagement — Attack & Technique Plan

Status: **Plan final.** Scope reference: `projects/crypto-h1/crypto-h1.draft.yaml` (DRAFT, project `crypto-h1`).  
Target Program: [`hackerone.com/crypto`](https://hackerone.com/crypto) (Crypto.com Bug Bounty Program).  
Program Signal Requirement: `-1.0 or higher` (trial reports consumed below threshold).

---

## 1. Context & Objectives

This document establishes the MITRE ATT&CK methodology and host-by-host test plan for executing Viper against the Crypto.com HackerOne bug bounty program.

Crypto.com is a high-stakes, regulated cryptocurrency exchange securing substantial user funds with a top bounty of $1,000,000 across 24 published scope assets. In this environment, uncontrolled scanning or unauthorized actions are strictly disqualifying. Program rules mandate:
- **Zero user impact:** No draining user or corporate funds, no blocking user access, no touching user or staff accounts.
- **Zero intrusive testing:** No denial of service (DoS), no brute-forcing, no social engineering, no malware.
- **Safety by design:** Non-destructive, detection-only probes with human approval gating for all active operations (`RiskLevel.ACTIVE`).

This plan focuses testing exclusively on non-account-requiring web applications, API endpoints, and microservices across the **Low Bounty Tier** and public **Extreme Tier Not Eligible** assets. All account-requiring workflows, smart contracts, compiled mobile apps, and explicitly excluded assets are defended by strict policy boundaries documented in [ADR 0013](file:///C:/Users/STSC/Desktop/Viper/docs/adr/0013-crypto-h1-scope-boundaries.md).

---

## 2. MITRE ATT&CK Enterprise Mapping

Each Viper tool and technique maps to standard MITRE ATT&CK Enterprise tactics and techniques. All actions operate strictly within detection and surface-mapping boundaries:

| ATT&CK Tactic | Technique ID & Name | Viper Tool / Mechanism | Operational Boundaries & Safety Invariants |
|---|---|---|---|
| **Reconnaissance** | **T1595.002** (Active Scanning: Vulnerability Scanning) | `nuclei` (HTTP-only profile, tags: `tech,exposure,misconfig`, severities: `info,low,medium`) | Strict rate limiting (`max_rate_rps: 4`, `-rl 4`, `-c 5`). No intrusive, dos, fuzz, bruteforce, rce, or sqli tags. |
| **Reconnaissance** | **T1595.002** (Active Scanning: Vulnerability Scanning) | `nmap` (TCP connect scan, service detection) | Bounded port scan (`80,443,8443`), unprivileged non-SYN scan. No aggressive timing (`-T4`), no raw packet crafting. |
| **Reconnaissance** | **T1596** (Search Open Technical Databases) | `passive-scan` (Certificate Transparency logs, public DNS records) | Zero target traffic generated; query third-party public registries only. |
| **Resource Development** | **T1583-adjacent** (Asset Identification & Scoping) | `projects/crypto-h1/crypto-h1.draft.yaml` | Machine-enforced boundary containing exact hostnames; URL-type assets noted in ambiguities. |
| **Initial Access** | **T1190** (Exploit Public-Facing Application) — *Surface Mapping Only* | `injection_probe` (XSS, SQLi, OS command, and URL redirect detection) | **Detection-only**: single-shot, marker-based probes (e.g. harmless math expressions or alphanumeric canary strings). Zero exploitation, zero payload execution, zero second-order payloads. Gated on human approval (`RiskLevel.ACTIVE`). |
| **Discovery** | **T1518** (Software Discovery) | `nuclei` (tech fingerprinting), `nmap` (banner grabbing) | Bounded inspection of public HTTP response headers, HTML meta tags, and TLS certificates. |
| **Discovery** | **T1087-adjacent** (API & Schema Enumeration) | `graphql_introspect` (GraphQL schema discovery) | Single read-only introspection query (`{__schema{types{name}}}`). Zero mutations, zero arguments, zero recursive queries, zero flooding. Human approval required (`RiskLevel.ACTIVE`). |
| **Credential Access** | **T1552.001** (Unsecured Credentials: Credentials In Files) — *Passive Detection* | `secret_scan` (JavaScript bundle static analysis) | Pure HTTP GET (`RiskLevel.PASSIVE`) of publicly served `.js` files. Static regex inspection for exposed keys (AWS, Bearer/JWT, internal domain names). Matching records redact secrets (first/last 4 characters only). Zero credential use or validation. |
| **Exfiltration** | *None* | **Never Performed** | Viper policy and architecture strictly prohibit data staging, extraction, or exfiltration. Findings report exposure evidence only. |

---

## 3. Asset-by-Asset Test Plan

Twelve non-account-requiring hostnames are authorized in `projects/crypto-h1/crypto-h1.draft.yaml`. The table below outlines the primary techniques, ATT&CK mapping, and rationale for each asset:

### 1. `js.crypto.com`
- **Program Tier:** Low Bounty Tier ($10–$500).
- **Primary Techniques:** `secret-scan` (T1552.001), `passive-scan` (T1596), `web-scan` (T1595.002).
- **Rationale:** Central JavaScript bundle and static asset CDN. JS bundles are the primary location where frontend developers inadvertently leak internal API routes, staging subdomains, backend service tokens, or client-side configuration secrets. Testing consists of fetching static `.js` bundles and analyzing them against fixed secret patterns with redaction.

### 2. `developer.crypto.com`
- **Program Tier:** Low Bounty Tier ($10–$500).
- **Primary Techniques:** `web-scan`, `template-scan` (T1595.002), `injection-test` (T1190), `service-detection`.
- **Rationale:** Public developer documentation and integration guides. Evaluated for exposed search form injection vulnerabilities (reflected XSS), documentation CMS misconfigurations (outdated frameworks, directory listings), and open redirect parameters in documentation references.

### 3. `developer-api.crypto.com`
- **Program Tier:** Low Bounty Tier ($10–$500).
- **Primary Techniques:** `web-scan`, `template-scan` (T1595.002), `injection-test` (T1190), `service-detection`.
- **Rationale:** Public developer API gateway. Assessed for unauthenticated endpoint discovery, CORS misconfigurations (permissive `Access-Control-Allow-Origin: *`), parameter injection in public lookup methods, and TLS/HTTP security header hardening.

### 4. `developer-platform-api.crypto.com`
- **Program Tier:** Low Bounty Tier ($10–$500).
- **Primary Techniques:** `web-scan`, `template-scan` (T1595.002), `injection-test` (T1190), `service-detection`.
- **Rationale:** Platform-level API gateway. Tested for unauthenticated route exposure, HTTP method tampering (OPTIONS, HEAD bypasses), and parameter validation flaws on public routes, while strictly respecting the 4 rps rate limit.

### 5. `travel.crypto.com`
- **Program Tier:** Low Bounty Tier ($10–$500).
- **Primary Techniques:** `web-scan`, `template-scan` (T1595.002), `injection-test` (T1190), `secret-scan` (T1552.001).
- **Rationale:** Crypto.com Travel portal service. Evaluated for frontend script exposures, travel booking search input sanitization (SQLi/XSS markers on search forms), third-party partner integration misconfigurations, and clickjacking/security header gaps.

### 6. `tickets.crypto.com`
- **Program Tier:** Low Bounty Tier ($10–$500).
- **Primary Techniques:** `web-scan`, `template-scan` (T1595.002), `injection-test` (T1190), `secret-scan` (T1552.001).
- **Rationale:** Event and sports ticketing portal. Evaluated for ticket category and search parameter handling, checkout redirect parameter validation (`url_injection_redirect`), and exposed staging or debug artifacts in frontend assets.

### 7. `tax.crypto.com`
- **Program Tier:** Low Bounty Tier ($10–$500).
- **Primary Techniques:** `web-scan`, `template-scan` (T1595.002), `injection-test` (T1190), `secret-scan` (T1552.001).
- **Rationale:** Cryptocurrency tax reporting and calculator service. Assessed for public informational page vulnerabilities, client-side calculator logic flaws, parameter reflection on contact or feedback endpoints, and cookie security flags.

### 8. `experiences.crypto.com`
- **Program Tier:** Low Bounty Tier ($10–$500).
- **Primary Techniques:** `web-scan`, `template-scan` (T1595.002), `injection-test` (T1190), `secret-scan` (T1552.001).
- **Rationale:** Brand experiences and VIP rewards portal. Assessed for content management system (CMS) exposures, promotional campaign landing page misconfigurations, and unescaped input reflection.

### 9. `web.crypto.com`
- **Program Tier:** Extreme Tier Not Eligible ($10–$5,000).
- **Primary Techniques:** `web-scan`, `template-scan` (T1595.002), `service-detection`, `secret-scan` (T1552.001), `injection-test` (T1190).
- **Rationale:** Core public web application frontend. High-visibility entry point evaluated for edge caching anomalies, security headers (CSP, HSTS), framework disclosure, and public form parameters. Deep authenticated flows are excluded.

### 10. `og.com`
- **Program Tier:** Extreme Tier Not Eligible ($10–$5,000).
- **Primary Techniques:** `web-scan`, `template-scan` (T1595.002), `service-detection`, `injection-test` (T1190).
- **Rationale:** High-value domain property operating under Crypto.com ownership. Evaluated for domain routing misconfigurations, virtual host routing, legacy application fingerprinting, and exposed administration interfaces.

### 11. `nadex.com`
- **Program Tier:** Extreme Tier Not Eligible ($10–$5,000).
- **Primary Techniques:** `service-detection`, `web-scan`, `template-scan` (T1595.002), `injection-test` (T1190).
- **Rationale:** North American Derivatives Exchange (Nadex) web portal (regulated derivatives exchange subsidiary). Assessed for unauthenticated informational web application surface, TLS configuration, and edge proxy header behaviors.

### 12. `merchant.crypto.com`
- **Program Tier:** Extreme Tier Not Eligible ($10–$5,000).
- **Primary Techniques:** `graphql-introspection` (T1518 / T1087-adjacent), `web-scan`, `template-scan` (T1595.002), `injection-test` (T1190).
- **Rationale:** Crypto.com Pay Merchant checkout portal. The program policy explicitly notes: *"merchant.crypto.com GraphQL DoS capped at $200"*, confirming that GraphQL is an active, acknowledged surface. `graphql_introspect` dispatches a single read-only schema dump query (`{__schema{types{name}}}`) to detect enabled introspection. No batch queries, mutations, or high-volume queries are permitted; `dos` remains globally forbidden.

---

## 4. Operational Safety & Execution Workflow

1. **Deterministic Rate Bounding:** `max_rate_rps: 4` is enforced by Viper's policy engine and propagated to tool invocations (`nuclei -rl 4`).
2. **Pre-Dispatch Human Gating:** All actions categorized as `RiskLevel.ACTIVE` (`injection_probe`, `graphql_introspect`) pause execution and require explicit operator CLI confirmation (`viper agent resume --decision ALLOW`).
3. **Egress Isolation:** The Cloud VM execution plane (`viper-crypto-lab`) enforces an egress allowlist containing only the 12 in-scope hostnames via `VIPER_EXEC_EGRESS_ALLOWLIST`. Any attempt to contact out-of-scope hosts fails at the network transport layer.
4. **Append-Only Hash-Chained Audit Trail:** Every planning decision, human approval, tool dispatch, and tool result is logged to `data/audit/crypto-h1.jsonl` with cryptographic SHA-256 hash chaining.
5. **Vulnerability Disclosure Policy:** Findings will be summarized in `docs/crypto-h1-run.md` with raw JSONL evidence. Any eligible vulnerability will be drafted as a HackerOne report for human review before submission.
