# Changelog

All notable changes are documented here. The project is milestone-driven (see
[`docs/implementation-roadmap.md`](docs/implementation-roadmap.md)); versions track milestones.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Weekly knowledge-base refresh owner guide (`docs/weekly-kb.md`): 60-second setup covering repository secrets (`SUPABASE_URL`, `SUPABASE_SECRET_KEY`), manual `workflow_dispatch` execution, outcome interpretation, and artifact downloads.
- Workflow guard tests (`tests/test_workflows.py`): offline YAML assertions ensuring full commit SHA action pinning, least-privilege permissions, absence of `pull_request_target`, schedule/dispatch triggers for weekly KB updates, and stability of required status check job names.

### Changed
- CI workflow health and concurrency: `.github/workflows/ci.yml` and `security.yml` configure concurrency to cancel superseded pull request runs while preserving push runs to main, declare explicit permissions, and harden status check aggregation.
- Dependency bumps: updated build and development dependencies including setuptools, pytest, ruff, mypy, and pydantic-settings.

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
