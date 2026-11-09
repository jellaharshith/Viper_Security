# Viper v1.0 Scope & v1.1 Backlog

This document establishes the authoritative functional boundary of the **Viper v1.0** release (Milestones M0 through M7) and details the prioritized **v1.1 backlog**, including the architectural and operational reasons why each backlog item was deferred.

---

## 1. What Viper v1.0 Includes

Viper v1.0 delivers an end-to-end, safety-first autonomous cybersecurity copilot for authorized penetration testing and bug bounty engagements. Every component is designed around strict human-in-the-loop governance, bounded agent execution, tamper-evident audit logging, and zero-trust remote execution.

### 1.1 Scope and Engagement Governance
- **Strict Scope Data Model (`viper.policy.models.Scope`):** Immutable Pydantic model with `extra="forbid"` defining `project_id`, `program_url`, `evidence_ref`, `in_scope` (exact hostnames, `*.domain` wildcards, CIDR ranges), `exclusions` (which strictly override inclusions), and `forbidden_techniques`.
- **Scope File Validation & Revision Tracking:** Scope files are loaded from verified YAML files (`viper.agents.runner.load_scope`) with a canonical SHA-256 revision hash (`scope.revision`) bound to all policy decisions and audit events.
- **LLM Scope Drafting Assistant (`viper.policy.scope_draft`):** Library supporting extraction of structured target scopes from unstructured program policies, generating ambiguity warnings, and requiring human validation and finalization before execution.

### 1.2 Local Chat & Cited Knowledge Base (RAG)
- **Local Model Inference:** Driven by Ollama (`hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF:Q4_K_M` or local GGUF models) without sending prompt or target data to third-party model providers.
- **Multi-Source Cybersecurity Corpus:**
  - CISA Known Exploited Vulnerabilities catalog (`cisa-kev:`).
  - MITRE ATT&CK Enterprise techniques (`attack:`).
  - OWASP Top 10 Web Application Security Risks (`owasp-top10:`).
- **Dual Vector Store Backends:**
  - Local embedded Qdrant (`VIPER_STORE=qdrant`) for zero-dependency offline use.
  - Remote Supabase pgvector (`VIPER_STORE=supabase`) for scalable, team-accessible embeddings.
- **Calibrated Retrieval Quality:** Pinned similarity threshold (`min_score = 0.70`), retrieval `top_k = 4`, prompt injection defenses, mandatory source citation extraction, and detection/warning for ungrounded citations.
- **Gated, Versioned KB Updates (`viper kb update`):** Staged updates against live collections with automated quality gates (`recall@4 >= 0.95`, regression <= 0.02) and atomic database/file pointer promotion and rollback (`viper kb rollback`).
- **Automated Weekly Maintenance (`.github/workflows/kb-weekly.yml`):** Automated weekly GitHub Actions workflow executing gated KB refreshes against Supabase, preserving runner statelessness.

### 1.3 Evaluation & Calibration Harness
- **Repeatable Offline Evaluation (`viper eval`):** Evaluation runner measuring retrieval recall@k, answer correctness, citation validity, and hallucination rates across frozen datasets (dataset v1 and v2).
- **Threshold Calibration:** Tools (`viper.eval.retrieval.calibrate`) to establish optimal similarity cutoffs across natural queries, definitions, and off-domain prompts.

### 1.4 Agent Loop & Policy Engine
- **LangGraph State Graph:** Resumable execution loop managing request intake, planning, policy evaluation, human approval checkpoints, remote tool dispatch, evidence analysis, and report generation.
- **Registry-Owned Tool Definitions (`ToolRegistry`):** Authoritative tool catalog with immutable risk classifications (`READ`, `PASSIVE`, `ACTIVE`, `INTRUSIVE`) and strict Pydantic argument schemas (`extra="forbid"`). Model overrides or risk tampering are strictly rejected.
- **Deterministic Policy Enforcement (`viper.policy.engine`):**
  - `READ` and `PASSIVE` actions within scope are automatically permitted.
  - `ACTIVE` actions targeting in-scope assets require explicit operator approval (`REQUIRE_APPROVAL`).
  - `INTRUSIVE` techniques or any action targeting excluded/out-of-scope assets are unconditionally rejected (`DENY`).
- **Pre-Dispatch Re-Evaluation:** Policy engine independently re-evaluates scope, permissions, and tool schemas immediately prior to execution, preventing time-of-check to time-of-use (TOCTOU) discrepancies.
- **Human Approval Boundary:** Trusted local CLI boundary (`viper agent resume --decision ALLOW|DENY`) capturing operator OS username (`getpass.getuser()`) and binding single-use approval IDs to specific action hashes.
- **Dual Planning Modes:** Deterministic plan ingestion from JSON files (`--plan`) or bounded opt-in LLM planner (`--llm`, max 8 actions, capped JSON decoding depth and response size).

### 1.5 Cloud Kali Execution Plane
- **Isolated Cloud Runner:** Dedicated Kali Linux VM in Google Cloud Platform running with `--no-address` (zero public ingress), accessible solely via Google Cloud Identity-Aware Proxy (IAP) SSH tunnels.
- **Headless HTTPS Exec API (`vmapi`):** Authenticated FastAPI service bound to `127.0.0.1:8443` on the VM, requiring TLS CA bundle verification and bearer token authentication.
- **Dual Client & Server Egress Allowlists:** Client-side (`RemoteExecutor`) and server-side (`vmapi`) validation ensuring scanner commands target only pre-approved hosts.
- **Real-Time Stream Processing:** Live scanner stdout streamed via Server-Sent Events (SSE) with strict wire caps (4 MiB), output capture ceilings (1 MiB), bounded line buffers (64 KiB), and total time/idle timeouts.
- **Process Lifecycle Control:** Full process-group signal management (`viper exec watch`, `pause`, `stop`, `takeover`, `release`) enabling operator emergency stops (SIGKILL) and temporary suspension (SIGSTOP).
- **Exclusive Control Lock:** SQLite-backed control lock preventing agent dispatch when a human operator assumes manual control.
- **Unprivileged Service Execution & Bootstrap:** Service runs as dedicated unprivileged system user `viper-vmapi` under systemd with `KillMode=control-group`. Automated and reproducible VM setup is provided via `deploy/vm-bootstrap.sh`.

### 1.6 Security Scanning Tools
- **Nmap (`/usr/bin/nmap`):** Authorized TCP port scanning with service detection and unprivileged port discovery against in-scope targets.
- **Nuclei (`/usr/bin/nuclei`):** Benign, HTTP-only vulnerability and technology detection with a frozen safety profile:
  - Protocol restriction: `-pt http` (enforcing HTTP protocol templates only).
  - Tags: `tech,misconfig` only.
  - Excluded tags: `dos,fuzz,intrusive,bruteforce,rce,sqli,xss`.
  - Severities: `info,low,medium` only.
  - Operational bounds: `-rl 5`, `-c 5`, `-timeout 10`, `-retries 0`, `-no-interactsh`, `-disable-redirects`.
  - Root-owned, read-only template directory (`/opt/viper/nuclei-templates`).
  - *Hardening boundary:* While `-pt http`, tag allowlists, and tag denylists enforce the HTTP protocol and severity envelope at the runner CLI level, curating and pinning a dedicated, independently reviewed HTTP template subset (rather than relying on broad community template updates) is scheduled as a v1.1 hardening item.

### 1.7 Findings Architecture & Traceable Reporting
- **Finding Schema v1.1 (`viper.findings.models.Finding`):** Standardized finding model with title, asset, tool, action ID, raw evidence, severity, confidence, reproducibility, remediation, references, audit refs, and additive v1.1 fields: `description: str = ""` and `cwe: list[str] = []` with backward-compatible defaults.
- **Deterministic Finding Enrichment (`viper.findings.enrich`):** Offline, pure enrichment pipeline populating generic descriptions, CWE classifications, and vendor references from a curated offline catalog (e.g. common HTTP security headers, technology disclosures, and standard service ports) without overwriting specific tool-supplied findings or mutating severity/confidence.
- **The Confirmed vs. Hypothesis Rule:**
  - `confidence="confirmed"` is granted **only** when deterministic tool parsers extract explicit positive evidence matching the approved asset.
  - Ambiguous states (`open|filtered`), model inferences, or observations on foreign hosts/redirects are labeled `confidence="hypothesis"`.
- **Finding Re-Derivation from Evidence:** Findings are dynamically re-derived at report generation from audited stdout and verified against SHA-256 output digests. Stored finding claims in checkpoints are never implicitly trusted.
- **Stakeholder-Ready Multi-Format Reports (`viper report`):**
  - **Human-Readable Markdown:** Persisted with exclusive file creation (`mode="x"`) to `data/reports/<thread>.md`, featuring an executive summary matrix, tool-level grouping, dynamic backtick fencing outgrowing hostile scanner backticks, pretty-printed JSON evidence (for valid JSON < 8 KiB), sanitized control/bidi character escaping, and an audit citation index.
  - **Machine-Readable JSON (`viper.report.formats.render_json`):** Export conforming to `"schema": "viper-report/1"` with summary metrics, structured findings, and resolved audit event citations.
  - **Industry-Standard SARIF 2.1.0 (`viper.report.formats.render_sarif`):** Full OASIS SARIF v2.1.0 export with rule deduplication by template ID/port, mapped severity levels (`note`, `warning`, `error`), and `viperFindingId/v1` fingerprints for automated vulnerability management pipelines.

### 1.8 Audit Integrity & Head Anchoring
- **Hash-Chained Audit Trail:** Append-only JSONL log (`data/audit/{project_id}.jsonl`) with genesis block (`seq=0`, `prev_hash=0*64`), per-event SHA-256 hashing, recursive secret sanitization, and exclusive file locking.
- **Honest Evidence Events v2:**
  - `tool_dispatch`: Intent to execute (never a valid citation target).
  - `tool_result`: Actual outcome, binding action ID, tool, simulation flag, and SHA-256 output digest.
- **Audit Verification & Head Anchoring:** CLI verification (`viper audit verify`) validating full chain continuity, detection of corrupted tails or payload edits, and mock RFC-3161 anchoring (`viper audit anchor`) with detailed anchor coverage reporting.

---

## 2. The Viper v1.1 Backlog

The following features were evaluated during v1.0 design and deliberately deferred to v1.1. Each entry details the functionality, operational value, and the technical reason for deferral.

### 2.1 OWASP ZAP (Zed Attack Proxy) Integration
- **Description:** Headless web application vulnerability scanning using OWASP ZAP's daemon mode and automation framework (spidering, passive inspection, active scanning).
- **Motivation:** Provides in-depth, authenticated application-layer testing (XSS, CSRF, header security, API analysis) beyond Nuclei's template-driven checks.
- **Reason Deferred from v1.0:** ZAP runs as a persistent JVM daemon exposing a REST/WebSocket API rather than a standalone CLI binary. Managing daemon startup, session contexts, memory overhead (1–2 GB RAM), and complex policy configurations would have added substantial operational overhead to the lightweight single-binary execution model established for Nmap and Nuclei in v1.0.

### 2.2 noVNC Browser Remote Desktop & Graphical Takeover
- **Description:** A web-based graphical desktop streaming interface (noVNC / TigerVNC) embedded into the cloud Kali VM, allowing operators to visually inspect and manipulate GUI security tools (e.g., Burp Suite, browser DevTools) through a browser.
- **Motivation:** Enables manual inspection and exploitation tasks requiring browser interactions or desktop GUIs directly within the isolated cloud execution environment.
- **Reason Deferred from v1.0:** Running a full X11/XFCE desktop environment and VNC-to-WebSocket bridge significantly increases VM compute and memory consumption (necessitating larger VM instances), expands the attack surface, and complicates authentication across the IAP tunnel. The headless HTTPS/SSE API with CLI process controls (`pause`, `stop`, `takeover`) achieved all core automation and emergency-stop requirements at zero GUI overhead.

### 2.3 Real RFC-3161 TSA & Sigstore Rekor External Anchoring
- **Description:** Cryptographic anchoring of audit log head hashes to external public or private Timestamp Authorities (RFC-3161 TSAs over HTTPS) and public transparency ledgers (Sigstore Rekor transparency log), with offline signature and inclusion proof verification.
- **Motivation:** Provides indisputable, third-party cryptographic proof that audit records and pentest evidence existed at a specific time and have not been altered since the assessment.
- **Reason Deferred from v1.0:** Generating and verifying ASN.1/DER PKCS#7 timestamp tokens and Rekor signed entry inclusion proofs requires substantial external cryptographic libraries (such as `cryptography`, `pyasn1`, and `sigstore-python`), as well as trusted root CA bundle management. v1.0 established the complete audit schema, mock provider, anchor file persistence, and CLI verification matrix, deferring heavy cryptographic verification dependencies to v1.1.

### 2.4 Scope Rate-Limit & Automation Policy Fields
- **Description:** Extension of the `Scope` model and policy engine to parse, store, and enforce program-specific rate limits (e.g., `max_rate_limit: 5`) and granular automation constraints (e.g., `automation_allowed: false` on `/checkout` or specific URL subpaths).
- **Motivation:** Allows automated enforcement of explicit bug bounty program rules that restrict scanning speeds or forbid automated testing on sensitive application workflows.
- **Reason Deferred from v1.0:** In v1.0, rate limiting is enforced uniformly at the tool invocation level (e.g., Nuclei fixed `-rl 5`), and scoping is strictly host- and IP-based. Enforcing path-level automation filters and dynamic scanner throttling requires deep URL-level policy evaluation across all tool arguments, which was scoped out to ensure the v1.0 policy engine remained simple, verifiable, and zero-defect.

### 2.5 Integrated SSH Takeover Shell
- **Description:** A native CLI command (`viper exec shell --project <id>`) that establishes an interactive terminal (PTY) session directly into the cloud Kali VM through the IAP tunnel, automatically acquiring the exclusive control lock.
- **Motivation:** Streamlines operator takeover when manual command-line exploration is needed, eliminating the need to manually invoke `gcloud compute ssh` and run lock commands separately.
- **Reason Deferred from v1.0:** Operators can already execute manual terminal commands via the standard Google Cloud SDK (`gcloud compute ssh --tunnel-through-iap`) alongside `viper exec takeover`. Implementing a cross-platform interactive PTY client inside the Viper CLI requires handling OS-specific terminal control sequences (Windows console modes vs. POSIX termios), which was deferred in favor of standard tooling.

### 2.6 National Vulnerability Database (NVD) CVE Feed Ingestion
- **Description:** Ingestion and vector embedding of the full National Vulnerability Database (NVD) CVE API 2.0 / JSON feeds into the Viper RAG knowledge base.
- **Motivation:** Broadens knowledge base coverage to encompass historical CVEs and vulnerabilities that have not been cataloged in CISA KEV.
- **Reason Deferred from v1.0:** The complete NVD corpus exceeds 250,000 records. Ingesting and embedding this volume would significantly inflate the vector database footprint (increasing storage costs and retrieval latency) and introduce noise into retrieval queries. Furthermore, the NVD API 2.0 enforces strict rate limits. CISA KEV, MITRE ATT&CK, and OWASP Top 10 provided high-signal, zero-noise vulnerability coverage optimal for v1.0.

### 2.7 PostgreSQL Operational Tables
- **Description:** Migration of agent checkpoints, control locks, and run metadata from local SQLite databases (`data/checkpoints/`) into centralized PostgreSQL tables (e.g., hosted on Supabase alongside pgvector).
- **Motivation:** Enables centralized, multi-operator concurrent access, persistent state sharing across developer machines, and web dashboard integrations.
- **Reason Deferred from v1.0:** Viper v1.0 was intentionally architected for single-operator local use with zero mandatory server infrastructure beyond the optional Supabase vector store. Local SQLite checkpoints provide instantaneous, zero-latency atomic transactions with no database network dependencies or migration overhead.

### 2.8 Multi-Job Dispatch & Parallel Execution
- **Description:** Capability for the agent or operator to dispatch and manage multiple concurrent security scanner jobs on the execution plane simultaneously (e.g., running Nmap and Nuclei in parallel).
- **Motivation:** Reduces total engagement execution time by executing complementary passive and active reconnaissance tasks concurrently.
- **Reason Deferred from v1.0:** Concurrent job execution on a single target introduces risks of rate-limit exhaustion, network contention, and out-of-order target impacts. Furthermore, managing process-group signals (SIGSTOP, SIGKILL) and multiplexed SSE output streams for concurrent processes increases execution engine complexity. Single-job dispatch ensured deterministic audit trails, straightforward stream capture, and reliable emergency stopping.

### 2.9 Reviewed HTTP Nuclei Template Subset & Template Pinning
- **Description:** Curation, offline security auditing, and cryptographic hash-pinning of a minimal, reviewed subset of Nuclei HTTP templates strictly restricted to benign technology and exposure checks, packaged directly with the deployment rather than relying on broad community template updates.
- **Motivation:** While v1.0 enforces `-pt http`, tag allowlists (`tech,misconfig`), and tag denylists (`dos,fuzz,intrusive,...`), community template updates can introduce new or modified templates with unexpected network behaviors or payloads.
- **Reason Deferred from v1.0:** In v1.0, the combination of fixed CLI flags (`-pt http`, `-tags`, `-etags`, `-severity info,low,medium`, `-no-interactsh`, `-disable-redirects`), unprivileged service execution, and root-owned read-only `/opt/viper/nuclei-templates` provides robust runtime containment. Manually auditing and maintaining an in-tree curated catalog of thousands of individual YAML templates is deferred to v1.1.
