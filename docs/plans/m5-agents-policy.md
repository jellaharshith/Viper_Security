# M5 specification: LangGraph agents + deterministic policy engine

Status: Draft (2026-11-07). Docs only. Cost: $0. No live targets.
Roadmap definition of done: approval checkpoints and an audit log work with no live targets.

## 1. Scope and non-goals
In: agent graph, policy engine, approval interrupt/resume, append-only audit log, stub/dry-run tool registry.
Out (M6+): the execution plane/VM, real scanners (Nmap/ZAP/Nuclei), network egress, desktop takeover, PostgreSQL.
**Invariant: M5 code never opens a network socket to a target and never spawns a security tool.**
Tools are stubs returning canned data or `DryRunResult`s. `allow_active_testing` stays `False` (config.py) and
the policy engine denies every action of risk level ACTIVE or higher while it is false.

## 2. Module map (existing empty packages)
| Package | Contents |
|---|---|
| `viper.policy` | `models.py` (Scope, Action, Decision, RiskLevel), `engine.py` (`evaluate(action, scope, settings, now) -> Decision`), `approvals.py` (Approval record, expiry check) |
| `viper.tools` | `registry.py` (Tool protocol: name, risk level, param schema, `dry_run()`), `stubs.py` (`kb_answer`, `scope_check`, `plan_scan` dry-run stubs) |
| `viper.agents` | `state.py` (typed state), `graph.py` (builder), `nodes.py`, `audit.py` (log writer/verifier) |
| `viper.execution` | stays minimal in M5: an `Executor` protocol and a `DryRunExecutor`; the real VM client is M6 |

Reuse: `rag.pipeline.answer()` for the `research` node, `Settings` for flags, `logging_setup` for redaction.

## 3. Agent graph
State (`TypedDict`): `request`, `project_id`, `scope`, `plan: list[Action]`, `decisions: dict[action_id, Decision]`,
`approvals`, `results`, `status` (maps to the architecture states DRAFT_PLAN, AWAIT_APPROVAL, RUNNING, COMPLETED, FAILED), `audit_seq`.

Nodes: `research` (calls `answer()`, read-only) -> `plan` (LLM proposes `Action`s; its output is data, never authority)
-> `policy_gate` (deterministic; each action gets ALLOW / REQUIRE_APPROVAL / DENY) -> `approval` (interrupt) ->
`execute` (stub/dry-run only) -> `report`. DENY routes straight to `report`; a rejected approval routes to `report`.
`execute` re-checks the decision and the approval itself (defense in depth, mirroring the "two enforcement points"
control in security-design.md), so a routing bug cannot skip policy.

## 4. Policy engine
- **Deny by default:** no scope, ambiguous scope, unknown tool, unknown risk level, or any evaluation error = DENY.
- **Scope:** `Scope` holds in-scope assets (exact hosts, domains, CIDRs), exclusions (win over inclusions), allowed and
  forbidden techniques, rate limits, program URL, permission-evidence reference. Matching uses normalized values
  (lowercase host, punycode, `ipaddress` parsing). Redirects and DNS results are not trusted in M5.
- **Risk levels:** `READ` (KB lookup, scope read) -> allow; `PASSIVE` (dry-run planning) -> allow if in scope;
  `ACTIVE` (any packet to a target) -> REQUIRE_APPROVAL, and DENY while `allow_active_testing` is false;
  `INTRUSIVE` (exploitation, credential attacks) -> always DENY in M5.
- **Purity:** `evaluate` has no I/O and takes an injected `now`, so it is exhaustively unit-testable.
- Free text from scope documents or tool output is never parsed for permissions (prompt-injection guard).

## 5. Approval checkpoints (LangGraph interrupt/resume)
Verified against the LangGraph docs (docs.langchain.com/oss/python/langgraph/interrupts, /graph-api, /thinking-in-langgraph):
- `interrupt(payload)` inside a node pauses the graph; it needs a checkpointer and a `thread_id` in `config["configurable"]`.
- Resume with `Command(resume=value)` on the same thread. `value` becomes the return value of `interrupt()`, and
  **the node restarts from its beginning** on resume, so code before `interrupt()` must be idempotent and side-effect free.
- `InMemorySaver` (`langgraph.checkpoint.memory`) for tests; the docs show `SqliteSaver` (`langgraph.checkpoint.sqlite`) for durability.
- The docs' current examples drive the graph with `graph.stream_events(..., version="v3")` and read `stream.interrupts` / `stream.output`.
- **Not verified:** whether `invoke()` surfaces `__interrupt__` in the version we will pin, and the exact package name/version
  of the sqlite saver. M5-1 pins versions and adds a contract test that fails loudly if this API shifts.

Approval payload = explicit target, tool, parameters, risk, `expires_at`, and a hash of the action. The resume value must carry
`{decision, approver, action_hash}`; `approval` checks hash and expiry (mismatch or expired = DENY). Approvals are single-use
and never carry over to a changed action.

## 6. Append-only audit log
JSON Lines, one event per line: `seq, ts (UTC), thread_id, event, actor (agent|policy|human), action_hash, decision, detail, prev_hash, hash`.
Tamper evidence: `hash = SHA-256(canonical_json(event without hash) + prev_hash)`; a verifier walks the chain and reports the first
broken `seq`. The file is opened in append mode only; there is no update or delete API. Secrets and tokens are redacted before
writing (reuse `logging_setup` redaction). Events: plan_proposed, policy_decision, approval_requested, approval_granted,
approval_denied, approval_expired, tool_dry_run, run_completed.
Limitation: a local hash chain proves internal consistency, not authenticity; anchoring the head hash externally is M6 work.
The schema later maps to the `audit_events` table.

## 7. Test strategy (no network, deterministic)
Fake `ChatModel` with scripted plans; fake embedder/store; `InMemorySaver`; injected clock. Tests: policy truth table;
adversarial cases (prompt injection in a scope document, out-of-scope redirect, host-case/IDN/CIDR edge cases, exclusion beats
inclusion, expired/replayed/changed-action approvals); graph pause -> resume -> complete; reject path; audit chain verify and
tamper detection; a fixture that monkeypatches `socket.socket.connect` to fail, proving no network I/O.

## 8. Milestones (PR-sized)
1. M5-1 Policy models + `evaluate` + tests (no LangGraph yet); pin LangGraph and add the interrupt-API contract test.
2. M5-2 Tool registry + stubs + dry-run results.
3. M5-3 Audit log writer/verifier + tests.
4. M5-4 Graph skeleton (research -> plan -> policy_gate -> report) with fakes.
5. M5-5 Approval interrupt/resume with expiry and hash checks.
6. M5-6 CLI `viper agent run|resume` and `viper audit verify` (dry-run only); ADR 0008 to Accepted.

## 9. Open questions for the user
1. Persist checkpoints in SQLite for M5, or in-memory only until M6?
2. What is the local "approver" identity (OS user, free text)? It is audit metadata, not authentication.
3. Scope input format: YAML per project (proposed, strict schema) or JSON?
4. Should PASSIVE actions need approval, or only ACTIVE?
5. Audit log location: git-ignored `data/` or a configurable path?
