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
| general-0 | What does SQL stand for? | tangential sources scored above 0.70 and the model cited them, so no label | retrieval + prompt | let the model reject off-topic sources (`NOT_IN_SOURCES`) |
| def-2 | Buffer overflow | same: related ATT&CK/KEV records cited | retrieval + prompt | same fix |
| def-4 | Public key cryptography | same | retrieval + prompt | same fix |

None of these is a missing capability of the model. Correction (2026-11-07): the unverified label is added by code,
not by the model. The three labelling failures happen because related-but-not-answering sources pass the cutoff and
the model cites them, so the answer counts as grounded.

## Gate rule (docs/model-evaluation-plan.md)
Train only if a measurable, repeatable failure exists that prompting, tooling or RAG cannot fix. Here prompting and
retrieval have not been exhausted: the labelling failures are a retrieval/prompt problem, `general-2` is a threshold problem.

## Decision
1. **No QLoRA run.** No Colab training spend.
2. Cheap follow-ups, each measured against the frozen v2 set on Colab: (a) strengthen the unverified-label instruction in `rag/pipeline.py`; (b) revisit the cutoff per source; (c) later, a nickname-to-CVE alias table from an external source.
3. Re-open M4 only if a re-run after (a) and (b) still shows a repeatable model-behavior failure. If it does: training data only from permission-cleared sources, never the held-out eval datasets; verify the Llama 3.1 Community License terms; adapter must beat this baseline without general or safety regression and needs human approval; keep the previous model for rollback.

## Caveat
Four failures out of 62 is a small sample, and the prompt change itself can regress other cases, so it must be re-evaluated on the full set, not on these four.

## Follow-up experiment (branch m4/unverified-label)
The grounded system prompt now says to use a source only if it directly answers the question and to start with `NOT_IN_SOURCES` otherwise; code then shows the reply as UNVERIFIED model memory. Measured on Colab against the frozen v2 set; results below.

### Result (Colab T4, 2026-11-07): rejected, code reverted
`eval/results/v2-colab-t4-notinsources-2026-11-07.json`: **57/62 (91.9%)** vs 58/62 for the baseline at the same cutoff. Invalid citations 0%.
- Fixed: `def-2` (buffer overflow now labelled unverified).
- Regressed: `nat-4` (the model wrote `NOT_IN_SOURCES` although the Citrix record was retrieved, so the answer lost its sources) and `general-1` (no label).
- Unchanged failures: `general-0`, `general-2`, `def-4`.
Conclusion: asking an 8B model to judge source relevance is unreliable and hurts a grounded case. `pipeline.py` is left as on `main`.
Remaining options, none urgent: per-source cutoffs, a reranker that judges relevance outside the generator, or accepting these four cases as known limits. QLoRA is still not justified.
