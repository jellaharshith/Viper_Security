# Round 2: M3 cross-review

Date: 2026-11-07. Reviewed local HEAD `7516661`, including recalibration commit
`a328062`, M5 spec `docs/plans/m5-agents-policy.md`, and ADR 0008.
Review only; implementation and dataset changes remain with their lane owners.

## M3: recalibration

No blocking defect found in `a328062`. The diff implements the recorded user decisions:
`Settings.min_score = 0.70`; only def-3 and def-13 change expectations; both retain
human-review markers; general-2 stays grounded; nat-4 remains a documented limit.
The answer loader handles `review: needs-human`, and CLI chat and answer evaluation
pass `settings.min_score` explicitly to `answer()`.

Recomputed from the committed top-10 evidence: all four retrieved hits for every
nat-0..11 case survive 0.70; general-2's best score is 0.6983 and none survive;
def-3's top record is attack:T1111 (0.8025), def-13's is attack:T1555.005 (0.8222).
These confirm the ADR's retrieval assertions, not answer correctness. The predicted
53/62 is explicitly unconfirmed and must remain so until a full answer evaluation.

Validation caveat for the Round 2 handoff: `run_eval(skip_llm=True)` does not create
an `answers` section, so it cannot establish invalid-citation rate. Report citation
quality as unmeasured in that run. Also `cmd_eval_run` currently uses runner's v1
default (src/viper/cli.py:162); use an explicit v2 runner call to validate the
combined KEV/ATT&CK/OWASP set. These are existing evaluation limitations, not
regressions introduced by this commit.

## M5: security/policy findings

### M5-1 [P1] Specify authoritative policy inputs

Spec lines 24-42 put scope and proposed actions in graph state, but do not define
who supplies validated scope or whether proposed risk is trusted. A model can
label `plan_scan` READ or replace scope unless the executor independently loads
trusted policy data. A deterministic evaluator alone does not establish trust.
Require registry-owned risk/parameter schemas, rejection of caller risk overrides,
strict validated scope loaded outside LLM-writable state, and a fresh evaluation
against current scope/settings immediately before each dispatch. Test lowered-risk
proposals, forged/expanded scope, forbidden techniques, and changed settings/scope
after an interrupt. Include these requirements in ADR 0008's enforcement contract.

### M5-2 [P1] Define approval origin, binding, and consumption

Spec lines 54-56 require a hash/expiry and single use, but resume data includes a
self-reported approver and no pending-approval identity. The same action hash can
occur across projects, threads, or repeated actions. Hash equality alone cannot
enforce single use or prove a human submitted the decision.
Restrict resume to the trusted local human CLI boundary (an OS-user audit label is
sufficient for M5; remote authentication is outside scope). Bind a pending approval
ID to project/thread/action ID, canonical tool/target/parameters, scope revision,
and expiry; validate a strict decision schema. Atomically consume the pending ID
before dispatch and define restart/retry semantics so replay cannot dispatch twice.
Test duplicate resumes, identical actions in different threads, expired records,
checkpoint replay, and concurrent attempts. Denials must override approval.

### M5-3 [P1] Replace the nonexistent redaction dependency

Spec lines 21 and 61-62 say to reuse `logging_setup` redaction. Its `JsonFormatter`
currently emits `record.getMessage()`, arbitrary extras and formatted exception
text without a redaction pass (src/viper/logging_setup.py:22-32).
`Settings.redacted()` only masks typed settings fields; it cannot sanitize arbitrary
audit details. Require a dedicated allowlisted audit-detail schema and sanitization
before serialization/hash calculation. Test nested secrets, tool/model text,
exception strings, tokens and cookies with synthetic sentinel values. Never persist
raw scope evidence or resume payloads merely because they are JSON-serializable.

### M5-4 [P2] Define fail-closed audit writes and recovery

Spec lines 58-65 define a hash format but no behavior for append failure, an invalid
existing tail, or concurrent writers. Execution can otherwise proceed without its
approval/dispatch evidence, and simultaneous appends can fork the chain.
Require a single writer/lock, verification before append, deterministic genesis and
sequence rules, and failure before dispatch if required audit writes fail. Define
partial-line/restart handling; test unwritable storage, corruption and contention.
Keep the stated limitation that an unanchored local chain cannot detect every
rewrite or valid-prefix truncation; do not promise authenticity.

### M5-5 [P2] Align offline scope and verification

Spec lines 9, 21 and 67-71 permit research via `answer()` while promising no network
I/O; ADR 0008 decision 5 promises the latter too. Real answer dependencies use
Ollama and can use Supabase, so this is not automatically an offline path.
Choose an explicit M5 runtime contract: canned research/fakes for fully offline
runs, or separately documented permitted inference/KB endpoints with no target
egress. Keep execution restricted to the fixed stub registry even if environment
settings enable active testing. Patching only `socket.socket.connect` does not
prove the invariant: UDP `sendto` and subprocess launches are uncovered. Add
negative tests for target egress and subprocess dispatch, and a positive test that
the intended approval interrupt is reachable with a stub action while ACTIVE is
denied. The current risk table otherwise provides no default approval path.

## Validation and limits

Using the shared main virtual environment outside the sandbox (the sandbox could
not access its base interpreter): pytest **160 passed**; Ruff passed; mypy passed
for **30 source files**. `git diff --check` passed before this report was added.
These local checks do not establish hosted CI or the Python-version matrix.
No live DB, target, Ollama, or answer evaluation was run for this review.

Checked the official [LangGraph interrupt documentation](https://docs.langchain.com/oss/python/langgraph/interrupts):
the documented checkpointer/thread/resume and node-restart behavior supports the
spec's core design. Package pinning and the proposed contract test remain necessary;
documentation review is not a test of an installed LangGraph version.
