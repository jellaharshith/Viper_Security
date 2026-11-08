# Architecture (Hybrid, v1.1)

Source of truth for requirements: `../docs/requirements.md`.
This document refines it into a **three-plane hybrid** plus an independent knowledge pipeline.

## Planes

| Plane | Where | Job |
|---|---|---|
| Training | Google Colab / cloud GPU (CUDA) | Verify checkpoint, prepare data, QLoRA, evaluate, export |
| Local | Laptop (CPU, Ollama) | Test downloaded model, chat, evaluate, run LangGraph agents + policy |
| Execution | Separate cloud Linux/Kali VM | Run security tools with GUI, takeover, emergency stop |
| Knowledge (independent) | Scheduled job + Qdrant | Weekly RAG refresh; never coupled to training |

```text
Colab QLoRA -> merge adapter -> GGUF + quantize -> download -> Local Ollama test
   -> LangGraph agents + deterministic policy -> secure API -> Cloud Kali VM tools
Weekly RAG pipeline runs independently and feeds retrieval for the local assistant.
```

## Key decisions
1. **Policy is deterministic code.** The LLM may propose; `viper.policy` decides. Scope is default-deny and re-enforced on the VM.
2. **Laptop is CPU-only** (Ryzen 5 PRO 8540U, 14.7 GB RAM, integrated GPU). It runs quantized GGUF via Ollama and never trains.
3. **Adapters do not run directly in Ollama.** Export path: merge LoRA into base, convert to GGUF, quantize.
4. **Baseline before training.** Evaluate the original model + RAG first; QLoRA only if measurably justified.
5. **Embedded Qdrant for the MVP** (no Docker). A persistent Qdrant is needed before weekly automation; CI runners are ephemeral and cannot host it.
6. **Burp Suite is manual-GUI only** (not headless-automatable). Nmap, ZAP, Nuclei form the automated core.
7. **Cloud VM is on-demand** with idle shutdown. Scanning from a cloud provider may violate its acceptable-use policy; check before any live use.

## Module map (`src/viper/`)
`llm` (Ollama client), `training` (export handling), `rag` (ingest/embed/retrieve), `agents` (LangGraph), `policy` (scope engine), `tools` (Tool Registry), `execution` (VM client), plus `config`, `logging_setup`, `cli`.

## Human control states
`DRAFT_PLAN -> AWAIT_APPROVAL -> RUNNING <-> PAUSED -> MANUAL_CONTROL -> COMPLETED | FAILED`; emergency stop revokes new jobs and terminates tracked process trees.

## Data entities
projects, program_scopes, test_plans, approvals, execution_jobs, findings, knowledge_sources, rag_index_versions, model_versions, audit_events (PostgreSQL introduced in M5/M6; not needed earlier).
