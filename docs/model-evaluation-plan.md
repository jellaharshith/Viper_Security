# Model Evaluation Plan

## Purpose
Create a repeatable baseline, then compare any change (new model, RAG change, QLoRA adapter) against it.

## Dimensions
General knowledge; cybersecurity knowledge; vulnerability analysis; hallucination rate; source grounding (does the answer match retrieved text); structured-output reliability; tool-call reliability; scope compliance; safety/authorization behavior.

## Method
1. Fixed evaluation set, stored versioned in the repo, **separate** from any training data.
2. Run each candidate with identical prompts, settings and RAG index version.
3. Record scores, model/adapter version, index version and hardware.
4. Re-run monthly and after material changes.

## Candidates (M2)
Foundation-Sec-8B variants (after license check) and one general instruct model of similar size. A security model may be weaker at general tasks and tool calling, so both are measured.

## QLoRA gate (M4)
Train only if a measurable, repeatable failure exists that prompting, tooling or RAG cannot fix. Accept an adapter only if it improves the target metric with no unacceptable regression in general and safety scores, then require human approval. Keep the previous version for rollback.

## Hardware note
Local runs are CPU-bound, so evaluation sets stay small at first and run in batches.

## Verified model facts (2026-11-04)
Variants on Hugging Face under `fdtn-ai`: Foundation-Sec-8B (base, card: Apache-2.0, derived from Llama-3.1-8B), -Instruct, -Reasoning, and 1.1-Instruct; Cisco publishes Q4_K_M and Q8_0 GGUFs. Instruct/Reasoning ship Llama 3.1 Community License plus Cisco Apache-2.0 changes (NOTICE.md). M1 uses 1.1-Instruct Q4_K_M. Reasoning is an M2 comparison candidate (it emits long reasoning traces, which is slow on CPU).

## M2 harness: how to use it
```powershell
.\.venv\Scripts\python.exe -m viper.cli eval build                       # regenerate frozen datasets (only on purpose: changes the dataset hash)
.\.venv\Scripts\python.exe -m viper.cli eval run --tag my-run --skip-llm  # retrieval only, ~10 s
.\.venv\Scripts\python.exe -m viper.cli eval run --tag my-run             # full, ~7 min on this CPU
.\.venv\Scripts\python.exe -m viper.cli eval compare eval/results/a.json eval/results/b.json
```
- Datasets: `eval/datasets/retrieval.jsonl` (100 positives in 3 query styles, 30 negatives), `answers.jsonl` (22 cases in 6 categories). **Held-out: never use for training (M4).** Each report stores the dataset hash; `compare` warns when hashes differ.
- Checks are deterministic code (substring, JSON parse, label, citation validity). No LLM judge. Safety cases use a keyword heuristic and are flagged for **human review**; they measure model manners, not security (the deterministic policy engine in M5 is the control).

## M2 baseline and results (Foundation-Sec-1.1-8B-Instruct Q4_K_M, CISA KEV snapshot 2026.11.04, 1,768 records)

| Run | Pass | general | json | recall@4 | Notes |
|---|---|---|---|---|---|
| baseline (v1, min_score 0.55) | 86.4% | 0/3 | 3/3 | 97% | irrelevant KEV records attached to general questions |
| + prefixes, 0.65 | 86.4% | 0/3 | 3/3 | 99% | removed off-topic noise, no end-to-end change |
| + citation required everywhere | 77.3% | 1/3 | 0/3 | 99% | **regression**: JSON replies have no room for [n] |
| final (citation rule on semantic path only) | **90.9%** | 1/3 | 3/3 | 99% | adopted |

Safety (human-reviewed): all 4 answers decline malware / unauthorized access and point to written permission.
Mean latency about 18 s per answer once the model is loaded (23-35 s on first calls).

### Known limitations (carry into M3/M4)
- **Security-adjacent definition questions** (SQL, TLS, XSS) still attach KEV records: embeddings measure topical closeness, not answerability. Two of three still fail; expected to improve when OWASP/ATT&CK are indexed.
- **Citation presence is a weak signal**: the model can cite `[1]` while saying it does not help, or blanket-cite `[1], [2], [3], [4]`. Real faithfulness checking needs claim-level verification (candidate for M3).
- The 12 "natural" questions used to choose the cutoff are not yet in the frozen datasets (n is small). Add them in a dataset v2, which changes the hash on purpose.
- Gold answers for `general` assume such questions should be UNVERIFIED; for XSS that expectation is arguable (KEV does contain XSS records). Kept unchanged to avoid tuning the test after seeing results; revisit in dataset v2.
- Single model evaluated. **No comparison model yet** (Reasoning variant, a general Llama/Qwen): needs a ~5 GB download each; requires approval.
- n=22 answer cases and temperature 0.2: differences of one case are within noise.
