# ADR 0010: Finding model, deterministic confidence classification, report persistence, and audit anchoring

Status: Accepted / As-Built (2026-11-08)

## Context

M5 established Viper's safety and policy core (deterministic evaluation, approval checkpoints, hash-chained audit logging, dry-run dispatch). M6 added the headless cloud Kali remote execution plane (`RemoteExecutor`, `vmapi`) with process controls and dual-layer egress filtering. However, M6 output remained raw execution stdout (`DryRunResult.summary`) without structured vulnerability analysis, finding validation, or stakeholder-ready reporting.

In Phase 4 of the Viper architecture, the agent transitions from an execution harness into an authorized pentest and bug-bounty copilot. This transition introduces critical reliability, safety, and governance challenges:
- **Hallucinated Vulnerabilities:** LLMs frequently mistake software version banners for confirmed vulnerabilities, fabricate CVE associations, or exaggerate severity without verifying exploitability.
- **Unverified Inferences:** Presenting speculative model hypotheses alongside verified scanner findings creates dangerous noise, potentially causing unauthorized client actions or discredited security reports.
- **Broken Provenance:** Stakeholders and bug bounty triage teams require incontrovertible proof that reported findings were produced by authorized scans against in-scope assets, backed by exact raw evidence and execution timestamps.
- **Output Truncation & Memory Exhaustion:** High-volume scanner outputs (such as extensive port scans or verbose HTTP probes) can exhaust system memory or corrupt database checkpoints if not bounded.
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

3. **Tool Output Capture with 1 MiB Ceiling:**
   `RemoteExecutor` captures job stdout by streaming `GET /jobs/{id}/stream` over verified TLS with bearer auth once the job reaches terminal `state == "done"`. Lines are collected, joined with newlines, hard-capped at 1 MiB (`MAX_OUTPUT_BYTES = 1024 * 1024`, truncating cleanly without error), and returned in `DryRunResult.output: str`. Stubs leave `output = ""`. Stream errors on finished jobs fail closed by raising `RemoteJobError`.

4. **Deterministic Output Parsers (No LLM in the Parser Path):**
   Tool output parsing (`viper.findings.parsers`) is implemented as pure, deterministic functions (`parse_nmap`, `parse_nuclei`) using strict regex and JSON schema matching. Anything not matching expected scanner formats (such as arbitrary prose, injected attacker prompts, or error noise) is discarded. ANSI control codes are stripped.

5. **Traceable Markdown Report Generation & Persistent Storage:**
   - `viper.report.generator.render_report` compiles findings and audit events into a standardized Markdown report:
     - Partitions into `## Confirmed findings` and `## Hypotheses`.
     - When no verified vulnerabilities exist, explicitly prints `No confirmed findings.`
     - Resolves audit citations to `[audit-N]` footnote markers. Mismatched threads or action IDs resolve to `Unresolved`.
     - Indents raw evidence inside four-space code blocks and escapes HTML entities.
   - Reports are automatically saved to `Settings.report_dir / f"{valid_thread(thread)}.md"` (default `data/reports/<thread>.md`).
   - Thread IDs are strictly validated (`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`), blocking directory traversal.
   - The CLI exposes `viper report --thread <thread>` to read and display saved reports.

6. **Honest Audit Logging Taxonomy:**
   Audit event types clearly delineate real target interaction from simulated dry-runs:
   - Real tool execution commits `tool_executed`.
   - Simulated execution commits `tool_dry_run`.
   - Lifecycle additions: `plan_proposed`, `findings_generated`, `report_generated`, `audit_anchored`, `run_failed`, `run_completed`.

7. **Opt-In, Fail-Closed LLM Planner:**
   - The LLM planner (`viper.agents.planner.LLMPlanner`) is opt-in via `viper agent run --llm --request <text>`, mutually exclusive with `--plan <file>`.
   - Enforces `MAX_ACTIONS = 8` to bound blast radius.
   - Validates proposals strictly against `Action.model_validate` and registry tool schemas; fails closed with `PlannerError` on syntax errors, duplicate IDs, or unknown tools.

8. **Audit Anchoring M7 Implementation & Limitation:**
   - Resolving ADR 0009 deferral, `viper.agents.anchor` implements cryptographic anchoring adapters (mock, RFC 3161 TSA, Sigstore Rekor).
   - **Documented M7 Limitation:** CLI anchoring (`viper audit anchor --project <id>`) is **MOCK ONLY for now**, appending receipts to `data/audit/<project>.anchors.jsonl`.
   - While TSA and Rekor HTTP submission adapters exist, real external receipts remain `UNVERIFIED` during `viper audit verify` because no offline cryptographic verifier (for TSA PKCS#7 or Rekor inclusion proofs) is integrated yet.
   - `anchor_verdict` evaluates receipts during verification: missing heads return `MISMATCH` (fails verification), tampered mock receipts return `TAMPERED` (fails verification), valid mock receipts return `CONSISTENT_ONLY` (passes verification), verified external receipts return `VERIFIED` (passes verification), and unverified external receipts return `UNVERIFIED` (advisory, does not fail verification).
   - In addition, reports list refused actions and policy reasons in a sanitized `## Denied actions` section.

---

## Consequences

- **Positive:**
  - **Zero Hallucinated Confirmations:** Model imagination cannot contaminate the confirmed findings list.
  - **Audit Provenance:** Every reported issue is linked directly to raw execution evidence and immutable audit hashes.
  - **Memory & Storage Safety:** 1 MiB stream ceiling and thread token validation prevent resource exhaustion and file overwrite attacks.
  - **Offline Safety:** Automated test suite runs 100% offline (364 tests green).
  - **Honest Telemetry:** Separate `tool_executed` vs `tool_dry_run` events ensure compliance reviews can distinguish real network actions from dry-runs.
  - **Transparent Enforcement:** Refused actions are clearly recorded with policy justification in `## Denied actions`.

- **Trade-offs & Limitations:**
  - **Mock Anchoring Only in CLI:** External TSA and Rekor receipts cannot be verified offline until trusted verifier libraries are added.
  - **Output Truncation:** Scans generating more than 1 MiB of output are truncated at the boundary, which may omit lower-priority trailing scanner lines.

---

## Resolved anchor verdict trust policy

1. **Anchor Verdict Matrix (`src/viper/agents/anchor_check.py`):**
   - Non-matching anchor heads return `("MISMATCH", True)` (verification failure: head missing from local log).
   - Corrupted mock tokens return `("TAMPERED", True)` (verification failure: token tampered or malformed).
   - Valid mock tokens return `("CONSISTENT_ONLY", False)` (passes verification, indicating internal consistency only).
   - Offline-verified external receipts return `("VERIFIED", False)` (passes verification).
   - Unverified external receipts return `("UNVERIFIED", False)` (non-fatal warning: external receipt without wired verifier).

---

## Alternatives considered

- **LLM-Synthesized Confidence Ratings:**
  *Rejected:* Allowing the LLM to assign "confirmed" based on text reasoning introduces substantial hallucination risks and violates Phase 4 core requirements.

- **Per-Event External Anchoring:**
  *Rejected:* Submitting an external timestamp or Rekor entry for every individual audit event introduces severe network latency. Anchoring the chain head covers the entire history.

- **Dynamic Plan Size Without Limit:**
  *Rejected:* Unbounded plans invite runaway execution and approval fatigue; capped at 8 actions.
