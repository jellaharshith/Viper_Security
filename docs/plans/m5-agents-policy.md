# M5 specification: LangGraph agents + deterministic policy engine

Status: Approved Draft (revised 2026-11-07 with user decisions). Docs only. Cost: $0. No live targets.
Roadmap definition of done: approval checkpoints and an audit log work with no live targets.

## 1. Scope and runtime contracts
- **In scope:** agent graph, deterministic policy engine, approval interrupt/resume, append-only tamper-evident audit log, stub/dry-run tool registry.
- **Out of scope (M6+):** execution plane / cloud Kali VM, real security scanners (Nmap/ZAP/Nuclei), live network target egress, desktop takeover, PostgreSQL audit database.
- **Execution invariant:** M5 code never opens a network socket (TCP/UDP) to a target, never spawns a security tool subprocess, and never performs exploitation. The execution engine in M5 is strictly fixed to `DryRunExecutor` dispatching only to registered tool stubs (`viper.tools.stubs`). Real execution does not exist in M5 regardless of the `allow_active_testing` flag.
- **Runtime contracts:**
  - *Offline CI / test contract:* Zero-network execution. All LLM calls and knowledge retrievals use deterministic fakes (`FakeChatModel`, canned responses, fake vector store). Sockets and subprocesses are monkeypatched to assert zero external calls.
  - *Local development contract:* May connect to local inference (e.g. Ollama on localhost) and local/configured KB lookup via `answer()`, but strictly forbids target egress.
  - *Approval checkpoint reachability:* To verify human-in-the-loop approval interrupt/resume without live targets or real network calls, the policy engine supports an approval-required path for simulated/dry-run actions (e.g., dry-run actions flagged with `RiskLevel.ACTIVE` tested under `allow_active_testing=True`, or explicit approval-required stub actions).

## 2. Module map (existing empty packages)
| Package | Contents |
|---|---|
| `viper.policy` | `models.py` (Scope with provenance and revision hash, Action, Decision, DecisionType, RiskLevel), `engine.py` (pure `evaluate(action, scope, settings, now) -> Decision`), `approvals.py` (`PendingApproval` record, strict decision schema, atomic consumption tracker, expiry check) |
| `viper.tools` | `registry.py` (Tool definition protocol: authoritative name, registry-owned `RiskLevel`, parameter schema, `dry_run()`), `stubs.py` (`kb_answer`, `scope_check`, `plan_scan` dry-run stubs) |
| `viper.agents` | `state.py` (typed graph state with trusted vs proposed separation), `graph.py` (StateGraph builder), `nodes.py` (research, plan, policy_gate, approval, execute, report), `audit.py` (dedicated sanitization/redaction, fail-closed hash-chain writer, verifier) |
| `viper.execution` | `executor.py` (`Executor` protocol, `DryRunExecutor` stub dispatcher with pre-dispatch policy re-check) |

Reuse: `rag.pipeline.answer()` for the `research` node (with canned/fake options in tests), `Settings` for configuration flags, `logging_setup` for standard CLI logging. Audit sanitization is handled independently in `viper.agents.audit`.

## 3. Agent graph & state architecture
### State separation (`TypedDict`)
Graph state strictly separates authoritative inputs from untrusted LLM outputs:
- **Authoritative / trusted fields (read-only to LLM):**
  - `project_id: str`
  - `thread_id: str`
  - `scope: Scope` (loaded from verified external project file with immutable `scope_revision: str`)
  - `settings: Settings`
  - `pending_approvals: dict[str, PendingApproval]`
  - `status: str` (`DRAFT_PLAN`, `AWAIT_APPROVAL`, `RUNNING`, `COMPLETED`, `FAILED`)
  - `audit_seq: int`
- **Proposed / mutable fields:**
  - `request: str`
  - `research_summary: str | None`
  - `plan: list[Action]` (actions proposed by the model containing only `tool_name`, `args`, and `action_id`)
  - `decisions: dict[str, Decision]`
  - `results: list[DryRunResult]`

### Node flow & two enforcement points
1. `research`: Gathers context via `answer()` (or canned stub in offline tests).
2. `plan`: LLM proposes a sequence of `Action` objects. **The LLM provides data, not authority.** Any risk level or permission flag supplied by the model is discarded.
3. `policy_gate`: Evaluates each action deterministically against registry-owned risk levels and authoritative `scope`. Yields `ALLOW`, `REQUIRE_APPROVAL`, or `DENY`. For `REQUIRE_APPROVAL`, it constructs a `PendingApproval` record.
4. `approval`: If any action requires approval, pauses via LangGraph `interrupt()`. Resumed only via the trusted local CLI boundary.
5. `execute`: **Pre-dispatch re-evaluation (second enforcement point).** Immediately before invoking the tool stub:
   - Re-evaluates current policy against current scope and settings to prevent stale execution if scope changed during pause.
   - Validates that required approvals match the pending approval ID, are unexpired, have valid local human approver metadata, and are atomically consumed.
   - Dispatches only to `DryRunExecutor`.
6. `report`: Synthesizes execution results or policy rejection reasons. DENY or failed audit routes straight to `report`.

## 4. Deterministic policy engine
- **Authoritative provenance:** Scope is loaded from a validated project configuration file (e.g. YAML with strict Pydantic validation) outside LLM-writable memory. Each scope carries a deterministic `scope_revision = SHA-256(canonical_json(scope_dict))`. Free text from scope documents, web research, or model text is never parsed for permissions.
- **Registry-owned risk & schemas:** The tool registry (`viper.tools.registry`) is the sole authority for tool parameter schemas and `RiskLevel`. Proposed actions specify only `tool_name` and `arguments`. Any model attempt to declare or lower a tool's risk level is rejected.
- **Deny by default:** Missing scope, unrecognized tool, parameter schema violation, ambiguous target, or evaluation error results in immediate `DENY`.
- **Scope matching:** Normalized comparisons (lowercase hostnames, punycode for IDNs, `ipaddress` parsing for IPv4/IPv6 and CIDR ranges). Exclusions strictly win over inclusions. Redirects and DNS responses are untrusted in M5.
- **Risk hierarchy:**
  - `READ`: KB lookup, local scope queries -> ALLOW.
  - `PASSIVE`: Dry-run planning, local stub checks within scope -> ALLOW if target in scope.
  - `ACTIVE`: Simulated target actions -> REQUIRE_APPROVAL; strictly DENY when `allow_active_testing=False`.
  - `INTRUSIVE`: Exploitation, credential attacks -> always DENY in M5.
- **Purity:** `viper.policy.evaluate(action, scope, settings, now) -> Decision` has zero I/O and takes an injected `now: datetime`, making it 100% deterministic and exhaustively testable.

## 5. Human approval checkpoints & lifecycle
- **Trusted resume boundary:** Approval decisions are accepted exclusively through the local CLI boundary (`viper agent resume`), capturing the local operator identity (`getpass.getuser()`) as audit metadata. Remote authentication is out of scope for M5.
- **Pending approval cryptographic & structural binding:**
  Each approval checkpoint generates a unique `pending_approval_id` bound to:
  `pending_approval_id = SHA-256(project_id + thread_id + action_id + scope_revision + action_hash + expires_at)`
  where `action_hash = SHA-256(canonical_json({tool_name, normalized_args, registry_risk_level}))`.
- **Strict resume payload schema:**
  `{pending_approval_id: str, decision: "ALLOW" | "DENY", approver: str, action_hash: str, timestamp: str}`.
  A decision of `DENY` immediately halts execution and routes to `report`. Hash mismatch, expired timestamp, scope revision mismatch, or missing pending ID fails closed with `DENY`.
- **Atomic consumption & restart idempotency:**
  In LangGraph, resuming via `Command(resume=...)` restarts the interrupted node from the beginning. To prevent replay attacks or duplicate dispatch:
  - Pre-interrupt node code is strictly idempotent and side-effect free.
  - Upon receiving the resume payload, the node verifies the pending ID is in state, matches the action, and has `consumed == False`.
  - The node atomically marks `consumed = True` and writes an `approval_consumed` audit event before proceeding to `execute`.
  - Replayed resumes or reuse of a consumed pending ID fail closed.
- **Checkpointer:** `InMemorySaver` for unit/integration tests; `SqliteSaver` for durable CLI thread resumption.

## 6. Append-only tamper-evident audit log
- **Independent sanitization & allowlist (replaces logging_setup dependency):**
  `src/viper/logging_setup.py` contains no redaction pass. `viper.agents.audit` implements an explicit allowlist schema and recursive sanitization filter before serialization and hashing:
  - Sensitive tokens (API keys, session cookies, bearer tokens, passwords, private keys) are scrubbed and replaced with `[REDACTED]`.
  - Nested dictionary structures, tool arguments, model text, and formatted exception strings are sanitized.
  - Raw unparsed scope evidence or arbitrary raw resume payloads are never written directly to the log.
- **Log format & hash chain:**
  JSON Lines, one event per line:
  `seq, ts (UTC ISO), thread_id, event, actor (agent|policy|human), action_hash, decision, detail, prev_hash, hash`
  - Genesis event (`seq = 0`): `prev_hash = "0" * 64`.
  - Sequence: strictly monotonic (`seq = prev_seq + 1`).
  - Hash formula: `hash = SHA-256(canonical_json(event_without_hash) + prev_hash)`.
  - Event types: `plan_proposed`, `policy_decision`, `approval_requested`, `approval_granted`, `approval_denied`, `approval_expired`, `approval_consumed`, `tool_dry_run`, `run_completed`, `run_failed`.
- **Fail-closed write policy:**
  Audit logging is a mandatory safety gate. If an audit write fails (disk full, lock failure, write error), the engine aborts immediately and refuses to dispatch the action. No action executes without prior committed audit evidence.
- **Single writer, locking & recovery:**
  - File locking (exclusive lock during verify-and-append) prevents race conditions and chain forking.
  - Tail verification: Before appending, the writer verifies the existing file's tail `seq` and `hash`. If the tail is corrupted or the hash chain broken, the writer halts and fails closed.
  - Partial-write handling: An unparseable or partial line at EOF triggers fail-closed recovery (clean truncate to last valid hash only via explicit CLI repair command).
- **Security limitations:**
  A local hash chain guarantees internal consistency and tamper detection against accidental modification or unprivileged edits. It does not provide cryptographic authenticity against an attacker with root write access who could rewrite the entire chain. External anchoring is deferred to M6.

## 7. Test strategy (no network, deterministic)
- **Isolation harness:** Fixture monkeypatches `socket.socket.connect`, `socket.socket.sendto` (UDP), and `subprocess.Popen` / `subprocess.run` to guarantee zero network egress and zero scanner invocation.
- **Policy truth table & adversary tests:**
  - Model attempting to claim `READ` or `PASSIVE` on an `ACTIVE` tool (assert model override is rejected).
  - Model injecting permissions or new scope into graph state (assert engine reads authoritative scope only).
  - Out-of-scope targets, IDN/punycode homoglyphs, CIDR boundary edge cases.
  - Exclusions strictly overriding inclusions.
  - Scope or settings modified during an approval pause (assert pre-dispatch re-evaluation denies execution).
- **Approval lifecycle tests:**
  - End-to-end interrupt -> CLI resume -> atomic consumption -> dry-run dispatch.
  - Reachability test: approval interrupt is reached and exercised using dry-run stub actions requiring approval while real ACTIVE execution remains denied.
  - Replay protection: attempting duplicate resume with the same `pending_approval_id` fails closed.
  - Expiry, action hash alteration, scope revision mismatch, cross-thread replay, and explicit human rejection.
- **Audit engine tests:**
  - Sanitization of nested dicts, authorization headers, bearer tokens, cookies, synthetic sentinels, and exception strings.
  - Fail-closed behavior on unwritable directory or file lock timeout.
  - Chain verifier detects modified payloads, altered `prev_hash`, missing intermediate lines, and partial writes.
- **LangGraph API contract test:**
  - Verifies pinned LangGraph `interrupt()`, `Command(resume=...)`, and checkpointer restart semantics against library updates.

## 8. Milestones (PR-sized)
1. **M5-1:** Policy models, registry-owned risk definitions, pure `evaluate()` engine, and policy unit tests (truth table, risk override rejection, scope boundary tests). Pin LangGraph and add interrupt contract test.
2. **M5-2:** Tool registry with strict parameter schemas, dry-run stubs, and `DryRunExecutor` with pre-dispatch re-evaluation.
3. **M5-3:** Audit log module with dedicated allowlisted sanitization, fail-closed file locking, hash-chain calculation, and verifier.
4. **M5-4:** LangGraph agent skeleton (`research -> plan -> policy_gate -> execute -> report`) with trusted/untrusted state isolation and deterministic fakes.
5. **M5-5:** Approval checkpoint node (`interrupt`/`resume`), `PendingApproval` cryptographic binding, atomic single-use consumption, restart idempotency, and CLI resume handler.
6. **M5-6:** CLI integration (`viper agent run|resume`, `viper audit verify` in dry-run mode); ADR 0008 marked Accepted.

## 9. Resolved design decisions
User decisions resolved and approved on 2026-11-07 (full trade-off analysis in `docs/plans/m5-open-questions.md`):
1. **Checkpoint persistence:** `SqliteSaver` in SQLite (durable storage in `data/checkpoints.db`) for CLI pause/resume across terminal sessions; `InMemorySaver` for automated pytest suites.
2. **Approver identity:** Local OS username (`getpass.getuser()`) recorded as non-spoofable audit metadata on the trusted local CLI boundary.
3. **Scope format:** YAML file per project (`projects/{project_id}/scope.yaml`) with strict Pydantic validation rejecting unknown keys, hashed into canonical JSON SHA-256 `scope_revision`.
4. **Approval threshold:** Human approval required only for `ACTIVE` actions; `READ` and verified in-scope `PASSIVE` dry-run actions execute without approval. Real active execution remains denied by default via `allow_active_testing=False`.
5. **Audit log storage:** Centralized, git-ignored `data/audit/{project_id}.jsonl` with configurable base path via `Settings.audit_dir`.
