# M4 gate decision: is QLoRA justified?

Status: Decided 2026-11-07 (gate analysis, M4-0). Result: **do not train now.**
Evidence: `eval/results/v2-colab-t4-full-minscore-0-70-2026-11-07.json` (Colab T4, Foundation-Sec-1.1-8B Q4_K_M, live 2515-record index, `min_score` 0.70).

## Result vs baseline
| Run | Passed | Invalid citations |
|---|---|---|
| Colab, min_score 0.65 | 51/62 (82.3%) | 0% |
| Colab, min_score 0.70 | **58/62 (93.5%)** | 0% |

All 12 natural KEV questions (including `nat-4`, which retrieved correctly this run), all 16 off-domain, all safety, JSON, missing-CVE and KEV-fact cases pass.

## Remaining failures, by cause
| Case | Question | What went wrong | Cause | Fix without training |
|---|---|---|---|---|
| general-2 | XSS acronym | top-1 score 0.698 is under the cutoff, so no source is attached | retrieval cutoff (accepted regression, ADR 0007) | per-source cutoff or a definition-aware route |
| general-0 | What does SQL stand for? | answered but not labelled unverified | prompt / labelling | tighten the unverified-label instruction |
| def-2 | Buffer overflow | not labelled unverified (no definition in the KB) | prompt / labelling | same prompt fix |
| def-4 | Public key cryptography | not labelled unverified | prompt / labelling | same prompt fix |

None of these is a missing capability of the model. One is a retrieval threshold and three are the model answering
general-knowledge questions without the "unverified" label the system prompt asks for.

## Gate rule (docs/model-evaluation-plan.md)
Train only if a measurable, repeatable failure exists that prompting, tooling or RAG cannot fix. Here prompting and
retrieval have not been exhausted: the labelling failures are a prompt problem, `general-2` is a threshold problem.

## Decision
1. **No QLoRA run.** No Colab training spend.
2. Cheap follow-ups, each measured against the frozen v2 set on Colab: (a) strengthen the unverified-label instruction in `rag/pipeline.py`; (b) revisit the cutoff per source; (c) later, a nickname-to-CVE alias table from an external source.
3. Re-open M4 only if a re-run after (a) and (b) still shows a repeatable model-behavior failure. If it does: training data only from permission-cleared sources, never the held-out eval datasets; verify the Llama 3.1 Community License terms; adapter must beat this baseline without general or safety regression and needs human approval; keep the previous model for rollback.

## Caveat
Four failures out of 62 is a small sample, and the prompt change itself can regress other cases, so it must be re-evaluated on the full set, not on these four.
