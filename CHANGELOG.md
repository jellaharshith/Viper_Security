# Changelog

All notable changes are documented here. The project is milestone-driven (see
[`docs/implementation-roadmap.md`](docs/implementation-roadmap.md)); versions track milestones.
Format follows [Keep a Changelog](https://keepachangelog.com/).

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
