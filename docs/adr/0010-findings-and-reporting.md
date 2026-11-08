# ADR 0010: Finding model, deterministic confidence classification, evidence events v2, report persistence, and audit anchoring

Status: Accepted / Hardened (2026-11-08)

## Context

M5 established Viper's safety and policy core (deterministic evaluation, approval checkpoints, hash-chained audit logging, dry-run dispatch). M6 added the headless cloud Kali remote execution plane (`RemoteExecutor`, `vmapi`) with process controls and dual-layer egress filtering. However, M6 output remained raw execution stdout (`DryRunResult.summary`) without structured vulnerability analysis, finding validation, or stakeholder-ready reporting.

In Phase 4 of the Viper architecture, the agent transitions from an execution harness into an authorized pentest and bug-bounty copilot. This transition introduces critical reliability, safety, and governance challenges:
- **Hallucinated Vulnerabilities:** LLMs frequently mistake software version banners for confirmed vulnerabilities, fabricate CVE associations, or exaggerate severity without verifying exploitability.
- **Unverified Inferences:** Presenting speculative model hypotheses alongside verified scanner findings creates dangerous noise, potentially causing unauthorized client actions or discredited security reports.
- **Evidence Binding & Checkpoint Integrity:** The audit chain guarantees that log files are append-only and tamper-evident, but checkpoint state in SQLite can be modified or replayed. Findings cannot be accepted as trusted facts from checkpoint memory; they must be cryptographically bound to raw tool output and audited digests.
- **Stream Exhaustion & Unbounded Inputs:** High-volume scanner outputs can exhaust memory or freeze streams. Bounded buffers and wire limits are required.
- **Terminal Injection & Display Tampering:** Raw tool output can carry ANSI escape sequences, OSC hyperlink/clipboard commands, or Unicode bidirectional overrides designed to deceive operators or execute commands upon copy/paste.
- **Tamper Vulnerability of Local Audit Logs:** ADR 0009 deferred external audit-head anchoring to M7. While the local SHA-256 hash chain (`data/audit/{project_id}.jsonl`) detects file tampering or truncation by unprivileged users, external notarization is required to prove timeline integrity.

See `docs/plans/m7-pentest-copilot.md`, `docs/plans/m6-execution-plane.md`, and `docs/adr/0009-execution-plane.md`.

---

## Decision

1. **Frozen Finding Data Model (Finding schema v1):**
   Viper establishes a strict, immutable Pydantic schema for pentest findings (`viper.findings.models.Finding`) configured with `extra="forbid"`. Findings contain:
   - Identifiers: `id` (deterministic hash of tool, action ID, and unique key), `source_tool` (`"nmap"` | `"nuclei"`), `source_action_id`.
   - Asset & Evidence: `affected_asset` (must match an in-scope target), `evidence` (raw scanner stdout excerpt, never model-generated prose).
   - Assessment: `severity` (`"info"` | `"low"` | `"medium"` | `"high"` | `"critical"`), `severity_rationale`, `confidence` (`"confirmed"` | `"hypothesis"`).
   - Remediation & Repro: `reproducibility` (POSIX shell command quoted via `shlex.quote`), `remediation`, `references` (NVD CVE URLs, vendor advisories).
   - Traceability: `audit_refs` (list of SHA-256 hashes of the exact `tool_result` audit log events that recorded the execution outcome).

2. **The Confirmed-vs-Hypothesis Rule:**
   In compliance with Phase 4 requirement §4.7 ("never claim a vulnerability was confirmed solely because an LLM predicted it"), Viper strictly separates empirical scanner proof from speculative inferences:
   - `confidence="confirmed"` is reserved exclusively for concrete scanner evidence produced by deterministic parsers on the approved target (e.g. an open TCP port verified by Nmap handshake, or a Nuclei template match with confirmed HTTP response).
   - `confidence="hypothesis"` is assigned to ambiguous scanner states (e.g. Nmap `open|filtered`), any lead or observation synthesized by an LLM, and foreign-host observations (where Nuclei matched a host differing from the approved target).
   - The LLM is structurally prohibited from creating or escalating a finding to `"confirmed"` status.

3. **Evidence Events v2 Architecture:**
   To guarantee that audit citations reflect actual execution results rather than dispatch intent, real execution records two distinct events:
   - `tool_dispatch`: Committed *before* dispatch, recording operational intent (`action_id`, `tool`). This event is never a citation target.
   - `tool_result`: Committed *after* dispatch, recording the execution outcome with `detail = {"action_id": ..., "tool": ..., "digest": sha256(output), "simulated": False}`.
   - The legacy event `tool_executed` is permanently removed.
   - Simulated stub runs record the single event `tool_dry_run`.
   - Results in state carry `audit_hash` bound to the `tool_result` event hash.

4. **Re-Derivation of Findings & Incomplete Analysis Warnings:**
   - Stored findings in checkpoints are treated as untrusted. The graph `analyze` node and `report` node invoke `evidence.rederive(results, events)` to reconstruct findings directly from raw output whose SHA-256 matches the audited `tool_result` digest.
   - If an output was truncated, malformed records were skipped (`skipped > 0`), an output digest mismatched, or no matching `tool_result` event exists, an analysis warning is generated.
   - The report includes an explicit `## Analysis warnings` section stating: `Analysis is INCOMPLETE; do not read missing findings as a clean result.`

5. **Bounded Tool Output Capture (1 MiB Ceiling & Wire Limits):**
   `RemoteExecutor` captures job stdout from `GET /jobs/{id}/stream` over verified TLS once the job reaches `state == "done"`. Reads use bounded 8 KiB chunks and a 64 KiB line buffer. Captured stdout is capped at 1 MiB (`MAX_OUTPUT_BYTES = 1024 * 1024`), while wire limits enforce a 4 MiB transfer cap and 120s timeout. Hitting any limit marks `DryRunResult.truncated = True`. Stubs leave `output = ""`.

6. **Deterministic Output Parsers & Foreign-Host Containment:**
   Tool output parsing (`parse_nmap_ex`, `parse_nuclei_ex`) operates as pure, deterministic functions returning `(findings, skipped_count)`. Parsers enforce strict resource budgets (JSON depth <= 32, lines <= 20K, total input <= 4 MiB, findings <= 500). Nuclei matches against foreign hosts are quarantined as hypothesis observations and never attributed as confirmed findings on the target.

7. **Traceable Markdown Report Generation & Exclusive Persistence:**
   - `render_report` partitions findings into `## Confirmed findings` and `## Hypotheses`.
   - Citations resolve strictly to authentic `tool_result` events matching thread ID, action ID, tool, and `simulated is False`. All other citations resolve as `Unresolved audit reference`.
   - Refused actions are reported in a sanitized `## Denied actions` section (`_safe` strips control characters, Markdown tokens, and links).
   - Reports are automatically saved to `Settings.report_dir / f"{valid_thread(thread)}.md"` (default `data/reports/<thread>.md`) using mode `"x"` (exclusive creation).
   - Thread IDs cannot be reused for new runs (`valid_thread` regex `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`), preventing cross-assessment state contamination or symlink attacks.
   - CLI verb `viper report --thread <thread>` displays the saved report.

8. **Terminal Safety & Visible Control Escaping:**
   - `render_report` exposes all C0/C1 control bytes as printable `\xNN` hex escapes and Unicode bidirectional directional characters as `\uNNNN` escapes in evidence and metadata.
   - `cli.py` applies `terminal_safe()` (stripping control and bidi characters while keeping newlines and tabs) when printing reports to the operator's terminal.

9. **Opt-In, Budgeted LLM Planner:**
   - The LLM planner (`viper.agents.planner.LLMPlanner`) is opt-in via `viper agent run --llm --request <text>`, mutually exclusive with `--plan <file>`.
   - Enforces strict budgets: `MAX_REPLY_CHARS = 65_536`, `MAX_DECODE_ATTEMPTS = 50`, `MAX_ACTIONS = 8`.
   - Validates proposals strictly against `Action.model_validate` and registry tool schemas; fails closed with `PlannerError`.

10. **Audit Anchoring Limitation & Verdict Verification:**
    - Resolving ADR 0009 deferral, `viper.agents.anchor` implements cryptographic anchoring adapters.
    - **Documented M7 Limitation:** CLI anchoring (`viper audit anchor --project <id>`) is **MOCK ONLY for now**, appending receipts to `data/audit/<project>.anchors.jsonl` with event `audit_anchored`. External TSA/Rekor receipts remain `UNVERIFIED` until an offline cryptographic verifier is integrated.
    - `viper audit verify` reports anchor sequence coverage (`covers seq 0-N of M`) and evaluates receipts via `anchor_verdict`:
      - `MISMATCH`: Head hash not in local chain (fails verification).
      - `MALFORMED`: Receipt token is not valid base64 (fails verification).
      - `TAMPERED`: Mock token modified/inconsistent (fails verification).
      - `CONSISTENT_ONLY`: Mock token valid (passes verification, internal consistency only).
      - `VERIFIED`: External receipt accepted by offline verifier (passes verification).
      - `UNVERIFIED`: External receipt without offline verifier (advisory pass).

---

## Consequences

- **Positive:**
  - **Zero Hallucinated Confirmations:** Model imagination cannot contaminate the confirmed findings list.
  - **Cryptographic Evidence Binding:** Findings are re-derived from tool output verified against audited SHA-256 digests. Checkpoint tampering is neutralized.
  - **Transparent Deficiencies:** Truncated scans, skipped records, and denied actions are surfaced explicitly in report warning sections rather than appearing as clean scans.
  - **Memory & Storage Safety:** 1 MiB stream ceiling, 4 MiB wire cap, and exclusive report creation prevent resource exhaustion and file overwrite attacks.
  - **Terminal Protection:** Control and bidi character sanitization blocks terminal-based prompt injection and clipboard hijacking.
  - **Offline Safety:** Automated test suite runs 100% offline (453 tests green).
  - **Honest Telemetry:** Distinct `tool_dispatch` and `tool_result` events separate intent from verified outcome.

- **Trade-offs & Limitations:**
  - **Mock Anchoring Only in CLI:** External TSA and Rekor receipts cannot be verified offline until trusted verifier libraries are added.
  - **Output Truncation:** Scans generating more than 1 MiB of output are truncated at the boundary, generating analysis warnings.

---

## Alternatives considered

- **Single Execution Audit Event (`tool_executed`):**
  *Rejected:* Committing an execution event before the call cannot capture the output digest, while committing it after cannot record intent if the network fails. The two-stage `tool_dispatch` / `tool_result` model cleanly separates intent from evidence.

- **Trusting Checkpointed Findings:**
  *Rejected:* LangGraph checkpoints store serialized finding dictionaries that could be modified or desynchronized from the audit log. Re-deriving findings from digest-verified output guarantees tamper resistance.

- **Silent Handling of Parser Failures:**
  *Rejected:* Discarding unparseable scanner lines without notification creates false confidence. Surfacing `## Analysis warnings` ensures operators know when data was lost.
