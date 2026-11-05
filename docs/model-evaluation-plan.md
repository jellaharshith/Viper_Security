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
