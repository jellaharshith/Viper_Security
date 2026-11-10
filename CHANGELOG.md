# Changelog

All notable changes are documented here. The project is milestone-driven (see
[`docs/implementation-roadmap.md`](docs/implementation-roadmap.md)); versions track milestones.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [1.1.0] - 2026-11-09 - v1.1: Multi-format reports, real RFC-3161 anchoring, scope limits, SSH takeover shell

### Added
- **Multi-Format Stakeholder & Machine Reports:**
  - Enhanced Markdown reports (`viper report --format md`): executive summary severity x confidence matrix, tool-level finding grouping, dynamic backtick code fences outgrowing hostile scanner backticks, pretty-printed JSON evidence (for valid JSON < 8 KiB), and sanitized visible control/bidi character escaping.
  - Machine-readable JSON export (`viper report --format json`): top-level `"schema": "viper-report/1"` with summary metrics, structured findings, and resolved audit citations.
  - OASIS SARIF 2.1.0 export (`viper report --format sarif`): rule deduplication by template ID/port, mapped severity levels (`note`, `warning`, `error`), and `viperFindingId/v1` fingerprints.
  - Finding Schema v1.1 (`viper.findings.models.Finding`): additive backward-compatible fields `description: str = ""` and `cwe: list[str] = []`.
  - Deterministic finding enrichment (`viper.findings.enrich`): offline pure table filling generic descriptions, CWE classifications, and vendor references for Nuclei templates and Nmap ports without mutating parser-extracted specifics.
- **Real RFC-3161 Audit Anchoring (`viper audit anchor --provider tsa --allow-network`):**
  - SHA-256 message imprint timestamping over HTTPS, retaining opaque DER response in base64-encoded `AnchorReceipt`.
  - Offline cryptographic verification via OpenSSL CLI (`openssl ts -reply`, `openssl ts -verify`) using `certifi` CA bundle or enterprise roots.
  - Mandatory historical verification via `-attime <epoch>` to validate tokens as of their generation timestamp, preventing expiration failures on short-lived TSA signing certificates.
  - Verified receipts vouched by a trusted root earn authoritative `VERIFIED` status in `viper audit verify`.
- **Enforced Scope Limits & Registry-Owned Techniques:**
  - Additive `Scope` model fields: `max_rate_rps`, `automation_allowed`, and `permitted_techniques` (lowercase technique slugs).
  - Registry-owned tool technique tags (`nmap` = `port-scan`, `service-detection`; `nuclei` = `web-scan`, `template-scan`) and default request rates.
  - Deterministic, fail-closed policy engine evaluations with exact contract deny strings for rate exceeding, automation bans, forbidden techniques, and unpermitted technique deviations.
- **Audited SSH Takeover Shell (`viper exec shell`):**
  - Interactive operator terminal connection to execution VM over IAP (`gcloud compute ssh --tunnel-through-iap`).
  - Gated by active exclusive control lock (`human:...`), strictly auditing `human_shell_opened` before launch, and running via fixed argument list without shell interpretation.
- **Scope Reader Hardening (`viper.policy.scope_draft`):**
  - Model prompt updated to extract v1.1 fields (`max_rate_rps`, `automation_allowed`, `permitted_techniques`).
  - Strips `host:port` entries (e.g. `127.0.0.1:3000`) and records a human note instead of failing the draft.
  - Ignores rate phrases (e.g. "no more than 5 requests per second") in the automation ban detector to prevent false-positive bans while catching real automation bans.
  - Mandatory ambiguity warnings on unmapped techniques and conservative `automation_allowed = False` defaults when automated tools are restricted.
- **Weekly KB Automation & CI Hardening:**
  - 60-second owner guide for weekly knowledge base refresh (`docs/weekly-kb.md`).
  - Offline CI workflow assertions (`tests/test_workflows.py`) guarding SHA-256 action pins, least-privilege permissions, and required job names.
  - Concurrency controls in `ci.yml` and `security.yml` canceling superseded PR runs while serializing main runs.

### Changed
- `viper agent run` automatically renders and persists all three report formats (`.md`, `.json`, `.sarif`) to `data/reports/` upon completion.
- Dependency bumps: updated build and development dependencies (setuptools >=84.2.1, pytest >=9.2.0, ruff >=0.17.3, mypy >=2.4.1, pydantic-settings >=2.16.2).

### Deferred to v1.2
- **OWASP ZAP Integration (F4):** Headless web application scanner daemon deferred to v1.2.
- **noVNC Browser Remote Desktop (F5b):** Embedded GUI streaming interface deferred to v1.2.
- **Real Test 1 Lab Backlog Items (`docs/real-test-1.md`):**
  - Namespaced execution plane job IDs by thread to prevent HTTP 409 collisions on re-runs.
  - Spot VM preemption detection with distinct unreachable-plane error handling and resume.
  - Human approval checkpoint timeout UX improvements (clearer error on 15-minute expiry).
  - Nuclei template and request counters per run to diagnose variance on rate-limited targets.
  - Expanded template profile coverage (exposures / spidering for `/ftp`, `/metrics`, and API documentation).
  - Planner target formatting hardening to reject URL inputs on host-only execution plane.

## [1.0.0] - 2026-11-08 - v1.0: Live nuclei, scope reader, weekly KB refresh (security-reviewed)

### Added
- Scope reader library and CLI (`viper scope draft`, `viper scope approve`): model proposes a structured YAML scope from unstructured bug bounty program rules; drafts are inert (`status: DRAFT`) until human validation; `scope approve --confirm <project>` records a hash-chained `scope_approved` audit event with audit-before-publication ordering before writing the final scope.
- Live Nuclei execution profile on remote execution plane: protocol restricted to HTTP (`-pt http`), strict tags (`tech,misconfig`), excluded tags (`dos,fuzz,intrusive,bruteforce,rce,sqli,xss`), severities (`info,low,medium`), rate-limited (`-rl 5`), and root-owned read-only templates.
- Automated weekly knowledge base update workflow (`.github/workflows/kb-weekly.yml`): scheduled (Mondays 03:00 UTC) and dispatch-triggered gated updates against Supabase pgvector; official SHA-256 archive verification for Ollama releases; graceful skipping when secrets are unconfigured; single `kb-weekly-database` concurrency queue.
- Reproducible VM bootstrap script (`deploy/vm-bootstrap.sh`): idempotent setup script for cloud execution VM with dedicated unprivileged `viper-vmapi` service account, local TLS generation, and systemd process group management.
- Comprehensive v1 scope document (`docs/v1-scope.md`) defining v1.0 capabilities and the prioritized v1.1 backlog (OWASP ZAP, noVNC desktop, real RFC-3161 TSA anchoring, scope rate-limits, SSH shell takeover, NVD source, PostgreSQL operational tables, multi-job dispatch, reviewed HTTP template subset).

### Security
- Comprehensive v1 security review addressing 9 findings:
  - Scopes published only after durable audit event append succeeds (audit-before-publication ordering).
  - Scope draft validation rejects shorthand/alternate IP notations (e.g. `127.1`) to prevent CIDR exclusion bypasses.
  - Scope draft validation rejects public-suffix wildcards (`*.co.uk`, `*.github.io`) using a pinned offline suffix list.
  - Verified SHA-256 checksum before extracting the Ollama Linux binary archive.
  - Serialized workflow database concurrency across git refs via constant `kb-weekly-database` group.
  - Unique per-run random tokens in KB staging collection names to prevent collisions.
  - Enforced `-pt http` protocol restriction on remote Nuclei execution.
  - Hardened VM deployment runbook and bootstrap to run `vmapi` as an unprivileged service with root-owned templates.
  - Reserved capacity for mandatory scope draft warnings against model ambiguity limits.
  - Aligned exact-target and port argument validation schemas across client planner and server tool runner.

### Changed
- Nuclei execution upgraded from passive response mode to active HTTP-only technology and misconfiguration scanning.
- ADR 0004 updated to record weekly automation via GitHub Actions and explain stateless runner safety with Supabase pgvector.

## [0.7.0] - 2026-11-08 - M7: Pentest copilot (live-validated)

### Added
- Finding schema v1 and deterministic `nmap` / `nuclei` parsers. `confirmed` only from parser evidence.
- Opt-in LLM planner (`viper agent run --llm`) with strict, fail-closed parsing and size/work budgets.
- Evidence model: real dispatch writes `tool_dispatch` then `tool_result` (SHA-256 output digest); findings are
  re-derived only from audited results, so missing, edited or unaudited results surface as report warnings.
- Traceable Markdown report with audit-hash citations, "Analysis warnings" and "Denied actions" sections;
  `viper report --thread`.
- `viper audit anchor` (mock) and anchor verdicts in `viper audit verify`.
- `RemoteExecutor` captures tool output over the job stream with identity-only encoding and hard byte/time budgets.
- `viper` console entry point; CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, issue templates.

### Security
- Independent review found 14 issues (parser confirmation logic, injection into reports/terminals, unbounded stream
  buffering, thread reuse, evidence binding, anchor verdicts); all fixed before release.

### Changed
- Real execution is audited as `tool_dispatch` / `tool_result` instead of reusing `tool_dry_run`.
- Reports are written once per thread id (exclusive create); thread ids cannot be reused.
- Repository layout: requirements moved to `docs/requirements.md`, lab plan to `projects/lab-scanme/plan.json`.

### Fixed (found by the live validation)
- The VM bootstrap installed zero nuclei templates (`-duc` turns `-update-templates` into a silent no-op); it now fails if
  fewer than 1,000 templates are installed.
- The nuclei profile was too large for the VM API's 300 s job limit: the `exposure` tag (about 6,600 extra requests and the most
  intrusive part) is dropped, and jobs now have a per-tool limit (nmap 300 s, nuclei 900 s).
- Unit tests no longer depend on a developer's `.env`; the bootstrap script is guarded against CRLF line endings.

### Fixed
- Cloud runbook: systemd unit module path, VM allowlist variable name, Windows port-forward flags.

## [0.6.0] - 2026-11-07 - M6: Cloud execution plane
- Remote execution client and VM-side Exec API (`vmapi/`): TLS, bearer auth, argument allowlist, process-group
  control; approve, watch, take over, pause and emergency-stop, live-validated on a GCP VM.

## [0.5.0] - M5: LangGraph agents and policy engine
- Deterministic scope/risk policy, expiring approvals bound to exact action, hash-chained audit log, dry-run executor.

## [0.4.0] - M3: Weekly RAG automation
- Gated knowledge-base updates (CISA KEV, MITRE ATT&CK, OWASP Top 10) with eval gate, atomic promote and rollback.

## [0.2.0] - M1/M2: Local chat and evaluation
- Cited RAG chat over CISA KEV and an evaluation harness with a recorded baseline.

## [0.1.0] - M0: Foundation
- Project skeleton, configuration, logging, tests, CI and documentation.
