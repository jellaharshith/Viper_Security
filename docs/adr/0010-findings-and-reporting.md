# ADR 0010: Finding model, deterministic confidence classification, and external audit anchoring

Status: Proposed (2026-11-08)

## Context

M5 established Viper's safety and policy core (deterministic evaluation, approval checkpoints, hash-chained audit logging, dry-run dispatch). M6 added the headless cloud Kali remote execution plane (`RemoteExecutor`, `vmapi`) with process controls and dual-layer egress filtering. However, M6 output remained raw execution stdout (`DryRunResult.summary`) without structured vulnerability analysis, finding validation, or stakeholder-ready reporting.

In Phase 4 of the Viper architecture, the agent transitions from an execution harness into an authorized pentest and bug-bounty copilot. This transition introduces critical reliability, safety, and governance challenges:
- **Hallucinated Vulnerabilities:** LLMs frequently mistake software version banners for confirmed vulnerabilities, fabricate CVE associations, or exaggerate severity without verifying exploitability.
- **Unverified Inferences:** Presenting speculative model hypotheses alongside verified scanner findings creates dangerous noise, potentially causing unauthorized client actions or discredited security reports.
- **Broken Provenance:** Stakeholders and bug bounty triage teams require incontrovertible proof that reported findings were produced by authorized scans against in-scope assets, backed by exact raw evidence and execution timestamps.
- **Tamper Vulnerability of Local Audit Logs:** ADR 0009 deferred external audit-head anchoring to M7. While the local SHA-256 hash chain (`data/audit/{project_id}.jsonl`) detects file tampering or truncation by unprivileged users, it cannot protect against an attacker with host or root privileges rewriting the log file and recomputing hashes.

See `docs/plans/m7-pentest-copilot.md`, `docs/plans/m6-execution-plane.md`, and `docs/adr/0009-execution-plane.md`.

---

## Decision

1. **Frozen Finding Data Model (Finding schema v1):**
   Viper establishes a strict, immutable Pydantic schema for pentest findings (`viper.findings.models.Finding`) configured with `extra="forbid"`. Findings contain:
   - Identifiers: `id` (deterministic hash of tool, action ID, and unique key), `source_tool` (`"nmap"` | `"nuclei"`), `source_action_id`.
   - Asset & Evidence: `affected_asset` (must match an in-scope target), `evidence` (raw scanner stdout excerpt, never model-generated prose).
   - Assessment: `severity` (`"info"` | `"low"` | `"medium"` | `"high"` | `"critical"`), `severity_rationale`, `confidence` (`"confirmed"` | `"hypothesis"`).
   - Remediation & Repro: `reproducibility` (exact CLI command), `remediation`, `references` (NVD CVE URLs, vendor advisories).
   - Traceability: `audit_refs` (list of SHA-256 hashes of the exact audit log events that recorded the dispatch and execution).

2. **The Confirmed-vs-Hypothesis Rule:**
   In compliance with Phase 4 requirement §4.7 ("never claim a vulnerability was confirmed solely because an LLM predicted it"), Viper strictly separates empirical scanner proof from speculative inferences:
   - `confidence="confirmed"` is reserved exclusively for concrete scanner evidence produced by deterministic parsers (e.g. an open TCP port verified by Nmap handshake, or a Nuclei template match with confirmed HTTP response).
   - `confidence="hypothesis"` is assigned to ambiguous scanner states (e.g. Nmap `open|filtered`) and any lead, observation, or attack path synthesized by an LLM.
   - The LLM is structurally prohibited from creating or escalating a finding to `"confirmed"` status.

3. **Deterministic Output Parsers (No LLM in the Parser Path):**
   Tool output parsing (`viper.findings.parsers`) is implemented as pure, deterministic functions (`parse_nmap`, `parse_nuclei`) using strict regex and JSON schema matching. Anything not matching expected scanner formats (such as arbitrary prose, injected attacker prompts, or error noise) is discarded. ANSI control codes are stripped.

4. **Traceable Markdown Report Generation:**
   `viper.report.generator.render_report` compiles findings and audit events into a standardized Markdown report:
   - Sections are partitioned into `## Confirmed findings` and `## Hypotheses`.
   - When no verified vulnerabilities or open ports exist, the report explicitly states `No confirmed findings`.
   - Every finding cross-references its backing audit record via `[audit-N]` footnote markers linking to an Audit Trail Citation table. Events from mismatched threads or unrecognized hashes resolve as `Unresolved`.
   - Raw evidence is enclosed in indented code blocks and HTML entities are escaped to prevent Markdown breakout or prompt-injection formatting attacks.

5. **External Audit-Head Anchoring (RFC 3161 TSA / Sigstore Rekor):**
   Resolving the deferral in ADR 0009, Viper implements `viper.agents.anchor` to cryptographically notarize the terminal SHA-256 hash (`prev_hash` of the final event) of the audit chain:
   - **Mock Provider (Default):** Offline CI and unit tests use `provider="mock"`, generating deterministic, local-only receipts with `externally_verified=False` and zero network calls.
   - **External Providers (Opt-in):** In live engagements, operators opt into external notarization (`allow_network=True`) via RFC 3161 Time-Stamp Authorities (TSA) or the Sigstore Rekor public transparency log.
   - Receipts are stored in `data/audit/{project_id}.anchor.json` and verified by `viper audit verify`. Network failures fail closed and redact provider credentials.

6. **Planner Proposes, Policy Decides:**
   The LLM test planner (`viper.agents.planner`) acts strictly as a recommender, translating high-level objectives into `list[Action]`. The policy engine (`viper.policy.engine`) evaluates every action against authoritative scope. The planner has no authority to execute actions, bypass approvals, or alter findings.

---

## Consequences

- **Positive:**
  - **Zero Hallucinated Confirmations:** Model imagination cannot contaminate the confirmed findings list.
  - **Audit Provenance:** Every reported issue is linked directly to raw execution evidence and immutable audit hashes.
  - **External Non-Repudiation:** Anchoring the audit head to an external TSA or transparency log guarantees that logs cannot be rewritten after the fact without detection.
  - **Offline Safety:** Default test suites and CI runs execute 100% offline using mock receipts and captured tool fixtures.
  - **Clear Stakeholder Communication:** Reports distinguish actionable, proven risks from speculative investigation leads.

- **Trade-offs & Limitations:**
  - Ambiguous or subtle vulnerabilities that scanners detect as potential issues remain categorized as `"hypothesis"` until an explicit confirmation tool or human verification is provided.
  - External anchoring requires internet connectivity and access to an RFC 3161 TSA or Rekor service during the anchoring step.
  - Scanner output formats that deviate from expected regex/JSON schemas will be ignored until dedicated parser patterns are added.

---

## Alternatives considered

- **LLM-Synthesized Confidence Ratings:**
  *Rejected:* Allowing the LLM to assign "confirmed" based on text reasoning introduces substantial hallucination risks and violates Phase 4 core requirements.

- **Per-Event External Anchoring:**
  *Rejected:* Submitting an external timestamp or Rekor entry for every individual audit event introduces severe network latency and rate-limiting issues. Because the audit log is a cryptographic SHA-256 hash chain, anchoring only the terminal head hash mathematically proves the integrity and sequence of all preceding events in the chain.

- **PDF or HTML Report Generation:**
  *Rejected:* Markdown provides a human-readable, diffable, version-controllable format that can be directly converted to PDF/HTML via pandoc or corporate documentation pipelines while minimizing runtime dependencies.

- **Single Unpartitioned Finding List:**
  *Rejected:* Presenting hypotheses and confirmed findings in a single merged table invites stakeholder confusion and false-positive escalation.
