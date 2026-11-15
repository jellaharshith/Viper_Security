# Implementation Roadmap

Rules: one milestone at a time; tests green before moving on; explicit approval before each milestone and before any paid resource.

| ID | Milestone | Done when | Cost |
|---|---|---|---|
| M0 | Foundation: skeleton, config, logging, tests, docs, git | lint/types/tests pass; `--health` runs | $0 |
| M1 | Local chat + cited RAG (original model) | Answers cite retrieved sources from a small versioned corpus | $0 |
| M2 | Evaluation harness + baseline (**DONE — baseline recorded; v1/v2 retrieval and answer eval**) | Repeatable scores recorded for original model | $0 |
| M3 | Weekly RAG automation (**DONE — automated via kb-weekly.yml; min_score 0.70; Supabase pgvector**) | Staged update, eval gate, atomic promote, rollback, report | $0-low |
| M4 | Colab QLoRA (gated by M2) | Candidate beats baseline without general regression; human approves | Colab free or ~$10/mo |
| M5 | LangGraph agents + policy engine (**DONE — validated with approval checkpoints and hash-chained audit**) | Approval checkpoints and audit log work with no live targets | $0 |
| M6 | Cloud Kali execution plane (**DONE — live-validated on a GCP Kali VM 2026-11-08**) | Approve a lab task, watch it, take over, pause, emergency stop | On-demand, <$50/mo |
| M7 | Pentest copilot + bug bounty workflow (**DONE - live-validated on a GCP VM 2026-11-08**) | Traceable report from an authorized/lab target | On-demand |

## Dependencies
M2 needs M1. M4 needs M2 (baseline) and a verified model license. M5 needs M1. M6 needs M5's policy engine. M7 needs M5 + M6.

## Next step
v1.1 is released (RFC-3161 TSA anchoring, enforced scope limits). **v1.2 in progress** (see CHANGELOG `[Unreleased]` and docs/development-progress.md): KB grown with CWE/NVD/EPSS public sources, OWASP ZAP baseline scanner added (code + deploy), fine-tune harness being staged. Remaining v1.2 backlog: audited SSH takeover shell (§3.3), noVNC desktop (§3.2), Postgres operational tables (§3.6), Sigstore Rekor (§3.9). Live/paid/Colab steps (ZAP daemon + live scan, NVD live fetch, full eval, any QLoRA run) are owner-gated.
