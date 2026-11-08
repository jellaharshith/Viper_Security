# Implementation Roadmap

Rules: one milestone at a time; tests green before moving on; explicit approval before each milestone and before any paid resource.

| ID | Milestone | Done when | Cost |
|---|---|---|---|
| M0 | Foundation: skeleton, config, logging, tests, docs, git | lint/types/tests pass; `--health` runs | $0 |
| M1 | Local chat + cited RAG (original model) | Answers cite retrieved sources from a small versioned corpus | $0 |
| M2 | Evaluation harness + baseline (**built; baseline recorded**) | Repeatable scores recorded for original model | $0 |
| M3 | Weekly RAG automation (**M3a-e built; `min_score` 0.70; full answer run at 0.70 pending**) | Staged update, eval gate, atomic promote, rollback, report | $0-low |
| M4 | Colab QLoRA (gated by M2) | Candidate beats baseline without general regression; human approves | Colab free or ~$10/mo |
| M5 | LangGraph agents + policy engine (**built, dry-run only**) | Approval checkpoints and audit log work with no live targets | $0 |
| M6 | Cloud Kali GUI lab (**headless plane built & dry-run wired; paid VM gated**) | Approve a lab task, watch it, take over, pause, emergency stop | On-demand, <$50/mo |
| M7 | Pentest copilot + bug bounty workflow | Traceable report from an authorized/lab target | On-demand |

## Dependencies
M2 needs M1. M4 needs M2 (baseline) and a verified model license. M5 needs M1. M6 needs M5's policy engine. M7 needs M5 + M6.

## Next step
M1 begins with verifying the Foundation-Sec-8B variants and license, then choosing a model to pull in Ollama. Requires your approval.
