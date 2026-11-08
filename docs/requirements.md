# Personal Cybersecurity AI Agent — Architecture & Product Design v1

**Date:** November 4, 2026  
**Status:** Proposed architecture (design only; not yet implemented)  
**Audience:** Beginner building a personal tool, with possible future open-source/SaaS expansion.

## 1. Product vision

Build a personal, text-based AI assistant for **authorized penetration testing and bug bounty research**. The assistant should:
- Answer general questions and specialize in cybersecurity.
- Read a bug bounty program's written scope and rules; ask for clarification when ambiguous.
- Propose test plans and request explicit approval before active testing.
- Run approved security tools in a **cloud-hosted graphical desktop**, not on the user's computer.
- Let the user observe tool execution, pause it, take over mouse/keyboard control, and stop it.
- Analyze tool results, distinguish confirmed findings from hypotheses, and draft reports.
- Refresh cybersecurity reference knowledge automatically each week.
- Fine-tune the model only when evaluation demonstrates a benefit.

**Not in v1:** voice commands, public SaaS, billing, multi-user accounts, unrestricted autonomous scanning, automatic deployment of unreviewed model updates.

## 2. Core design choices

| Decision | v1 choice | Reason |
|---|---|---|
| Interface | Text chat | Simplest starting point |
| Intended user | One person | Lower operational complexity |
| Base model candidate | Cisco Foundation-Sec-8B family | Security focus; exact checkpoint and license must be verified |
| Model location | User's local laptop | Private, personalized inference; subject to RAM/GPU capacity |
| Security tools | Isolated cloud Linux VM with GUI | Avoid local tool execution |
| GUI access | Browser remote desktop (e.g., Guacamole/noVNC) | Live visibility and manual takeover |
| Agent orchestration | Python + LangGraph | Explicit workflow states and approvals |
| Knowledge retrieval | Embedding model + Qdrant | Searchable, updatable cybersecurity references |
| Operational records | PostgreSQL | Projects, approvals, jobs, findings, audit trails |
| Automation | Scheduled workflow initially; more robust orchestrator later | Weekly maintenance without needless complexity |
| Model adaptation | QLoRA adapters when justified | Lower training memory requirements |
| Architecture style | Modular monolith with clear service boundaries | Personal-first, expandable later |

**Important:** An open-weight checkpoint is not automatically open-source. Verify model license, commercial rights, derivative-model rules, and redistribution restrictions before use. Also benchmark general Q&A and tool calling: a security-focused model may not meet both requirements by itself.

## 3. System architecture

```text
USER (TEXT CHAT / BROWSER)
       |
       v
LOCAL APPLICATION
  - Text interface
  - Cisco-family LLM (candidate)
  - Agent orchestrator and policy client
  - Report viewer
       |
       | Authenticated, encrypted API
       v
CLOUD CONTROL PLANE
  - Project and scope registry
  - Approval workflow
  - Job queue and execution policy
  - Audit logs and result storage
       |
       v
CLOUD EXECUTION VM (ISOLATED)
  - Linux GUI desktop
  - Authorized tools: Nmap, OWASP ZAP, Burp Suite, Nuclei
  - Visible terminal/GUI sessions
  - Restricted network destinations and rate limits
       |
       v
RESULTS -> VALIDATION -> REPORT -> LOCAL CHAT

SEPARATE KNOWLEDGE/TRAINING PIPELINE
Trusted sources -> clean/verify -> embeddings -> Qdrant -> evaluation
                                               |
                                  conditional QLoRA training
                                               |
                                benchmark -> human approval
                                               |
                                versioned local model update
```

The GUI session and execution API are **not the same thing**. A headless command will not automatically appear in a desktop window. For visibility, run tools in attached terminal/GUI sessions and expose structured live logs.

## 4. Modules and responsibilities

### 4.1 Text interface
Accept questions, program scope, test requests, and approvals. Show task status, evidence, and final reports. Voice is excluded from v1.

### 4.2 Model and inference
Load a licensed Cisco Foundation-Sec-8B checkpoint, optionally with a trained LoRA adapter. Run a baseline evaluation before choosing Base, Instruct, or Reasoning variants. Quantization may make local inference feasible, but hardware requirements depend on checkpoint, context length, quantization, and runtime.

### 4.3 Orchestrator
LangGraph maintains states such as `DRAFT_PLAN`, `AWAIT_APPROVAL`, `RUNNING`, `PAUSED`, `MANUAL_CONTROL`, `COMPLETED`, and `FAILED`. The model may *suggest* an action, but a separate deterministic policy engine decides whether execution is permitted.

### 4.4 Scope and policy engine
Store the program URL, explicit in-scope assets, exclusions, permitted techniques, forbidden techniques, automation limits, rate limits, and permission evidence. Default-deny ambiguous destinations or activities. Enforce restrictions again on the cloud execution server; never rely solely on an LLM's interpretation.

### 4.5 Cloud GUI execution
Use a dedicated cloud VM with an isolated Linux desktop. Tools run with least privilege, resource limits, bounded duration, and restricted egress. Expose the desktop through a secured browser gateway. Start the VM on demand and stop it when idle. Verify the cloud provider permits the intended security testing.

### 4.6 Human control
- **Manual:** user drives the cloud desktop; AI advises.
- **AI-assisted:** AI proposes actions, user approves, tools run visibly.
- **Limited autonomous:** only previously approved low-risk tasks within explicit policy boundaries; later milestone.

A takeover action acquires an exclusive control lock, pauses the agent, and hands mouse/keyboard control to the user. Resume requires a fresh state check. Emergency stop revokes new jobs and terminates tracked running processes; log the event.

### 4.7 Result analysis and reporting
Parse tool outputs into structured findings. Distinguish unverified leads from validated issues. Record evidence, affected in-scope asset, severity rationale, reproducibility, confidence, remediation, and references. Never claim a vulnerability was confirmed solely because an LLM predicted it.

## 5. Weekly RAG update pipeline

**Suggested cadence:** weekly, e.g. Sunday; schedule and timezone configurable.

1. **Trigger:** scheduler starts a versioned workflow.
2. **Collect:** fetch new/changed records from NVD, CISA Known Exploited Vulnerabilities, MITRE ATT&CK, OWASP and other permitted sources.
3. **Validate:** confirm source, timestamps, licensing, schema, and record identity.
4. **Normalize:** deduplicate, retain provenance, attach CVE/CWE IDs, dates, and source links.
5. **Chunk:** split long documents into coherent passages with metadata.
6. **Embed:** transform passages into vectors with a separate embedding model.
7. **Stage:** load into a temporary Qdrant collection/index.
8. **Evaluate:** run retrieval quality and citation checks; reject degraded updates.
9. **Promote:** atomically switch the active index if checks pass.
10. **Notify:** create a summary with additions, failures, and index version.

**Failure behavior:** retain the previous working index; retry safely without creating duplicates. Fresh CVE facts usually belong in RAG, not weekly model weight changes.

## 6. Model evaluation and QLoRA

**LoRA:** train small low-rank adapter matrices while keeping original model weights frozen.

**QLoRA:** load the frozen base model in a quantized form during training to reduce memory use, while training adapter parameters. This does not mean the entire quantized model is retrained.

**Proposed decision flow:**
1. Maintain a stable evaluation set for general Q&A, cybersecurity analysis, report quality, source-grounding, tool-call format, and safety/scope compliance.
2. Review evaluation results monthly and after material changes.
3. Fine-tune only when a measurable, repeatable failure suggests training would help more than prompting, tool improvements, or RAG.
4. Build a permission-cleared, curated dataset; separate training and held-out evaluation sets.
5. Train a versioned QLoRA adapter on a rented cloud GPU.
6. Compare the candidate against the existing model on both general and security tasks.
7. Require manual approval before deploying the adapter.
8. Preserve rollback artifacts and record dataset, code, hyperparameters, and evaluation scores.

**Risks:** catastrophic forgetting, overfitting, poor-quality security labels, evaluation contamination, and training on confidential bug bounty reports without permission.

## 7. Local deployment and cloud synchronization

Cloud training produces a signed or checksummed, versioned adapter/model package. The local application downloads only an approved release, verifies its integrity, runs a smoke test, and switches versions with rollback support. RAG can be hosted remotely or synchronized to a local read-only index; this is a separate choice from model inference. A local 8B model still needs sufficient laptop memory even when tools run in the cloud.

## 8. Security and operational controls

- Require documented authorization and program-rule compliance for every target.
- Deny out-of-scope targets at the policy layer and network layer.
- Require human approval before active testing, with explicit target, tool, parameters, and expiry.
- Enforce rate limits, timeouts, resource quotas, and restricted egress.
- Use short-lived credentials, encrypted transport, secrets management, and audit logging.
- Protect bug bounty evidence, cookies, tokens, and personal data; redact sensitive material in reports and logs.
- Do not expose remote desktop or management APIs publicly without strong authentication and access controls.
- Prevent concurrent human/AI desktop control through locking.
- Provide stop, cancellation, and cleanup paths; verify terminated processes.
- Separate training, RAG indexing, and security-testing environments.

## 9. Suggested backend data entities

- `projects`: name, owner, status.
- `program_scopes`: assets, exclusions, rules, permission references, timestamps.
- `test_plans`: proposed actions and policy assessment.
- `approvals`: approver, action, scope, parameters, expiry, decision.
- `execution_jobs`: tool, container/VM, status, logs, timestamps.
- `findings`: evidence, severity, confidence, validation state, remediation.
- `knowledge_sources`: URL, license, fetched/updated timestamps, checksum.
- `rag_index_versions`: embedding version, dataset snapshot, evaluation result.
- `model_versions`: base checkpoint, adapter, evaluation, approval, rollback.
- `audit_events`: actor, action, timestamp, outcome.

## 10. Build phases and acceptance criteria

### Phase 1 — Foundation and knowledge
- Select and license-check model; benchmark general/security Q&A.
- Run a local text-only prototype.
- Ingest a small trusted cybersecurity corpus into Qdrant.
- Create weekly scheduled RAG refresh and rollback.
- **Done when:** queries return source-grounded answers, refresh is repeatable, and failures preserve the last good index.

### Phase 2 — Model customization
- Create an evaluation harness and baseline scores.
- Curate a small supervised dataset.
- Run optional cloud QLoRA training and compare against baseline.
- Implement artifact versioning, approval, and rollback.
- **Done when:** candidate shows measurable improvement without unacceptable general-task regression.

### Phase 3 — Cloud GUI lab
- Deploy an isolated cloud Linux GUI VM with secure browser access.
- Integrate a small allowlisted tool set in a test lab.
- Add explicit scope registry, approval checks, execution logs, pause, takeover, and emergency stop.
- **Done when:** the user can approve a lab task, observe execution, take control, stop it, and receive results.

### Phase 4 — Pentesting copilot
- Add planning, structured result parsing, finding validation, and report generation.
- Test only against intentionally vulnerable labs or clearly authorized targets.
- **Done when:** a full authorized workflow produces a traceable report without out-of-scope actions.

### Future — Open-source or SaaS
Potential additions: multi-user identity, tenant isolation, per-user VMs, quotas, billing, centralized operations, and public documentation. Release only code and materials whose licenses permit redistribution; exclude private findings, credentials, and training data.

## 11. Main tradeoffs and open decisions

1. **Exact Cisco checkpoint:** Base vs Instruct vs Reasoning, license, tool-calling reliability, general Q&A quality.
2. **Laptop capacity:** RAM/GPU, operating system, inference runtime and quantization.
3. **Cloud provider and budget:** VM size, GPU rental, storage, idle shutdown, egress costs.
4. **RAG location:** cloud-hosted search vs synchronized local index.
5. **Remote desktop:** Guacamole vs noVNC; GUI visibility and takeover implementation.
6. **Program policies:** some bug bounty programs prohibit automated scanning or particular testing techniques.

## 12. Recommended first implementation milestone

Before any live security-tool automation, demonstrate a **local text chat assistant that reads a sample vulnerability report and cites a small, versioned RAG knowledge base**. Add weekly update automation and evaluation next. Build the cloud GUI lab only after policy and approval controls are specified and tested.

---

**Project principle:** Personal-first, modular, scope-aware, human-controlled, observable, and recoverable. No unapproved live-target testing.
