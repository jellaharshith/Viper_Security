# ADR 0008: LangGraph agents with a deterministic policy engine

Status: Proposed (revised 2026-11-07 after codex-m3 Round 2 review)

## Context
M5 introduces autonomous agents that propose security-testing plans. The LLM is an untrusted component susceptible to prompt injection, hallucinated scope, and malicious parameter manipulation. Authoritative access control, human approval gates, and tamper-evident audit logging cannot rely on LLM outputs or unvalidated state. See `docs/security-design.md` and `docs/plans/m5-agents-policy.md`.

## Decision
1. **Model separation & registry-owned risk:** Agents are implemented as a LangGraph `StateGraph`. The LLM proposes candidate `Action` objects specifying only `tool_name` and `arguments`. Tool risk levels and parameter schemas are strictly owned by `viper.tools.registry`; model-supplied risk levels are rejected. Authoritative scope is loaded outside LLM-writable memory.
2. **Deterministic policy & two enforcement points:** `viper.policy.evaluate` is a pure, deny-by-default function and the sole authority for `ALLOW`, `REQUIRE_APPROVAL`, or `DENY`. In M5, active and intrusive actions are denied while `allow_active_testing` is false. Policy is evaluated at the `policy_gate` node and independently re-evaluated immediately before dispatch in `execute` to guard against stale state or changed scope.
3. **Cryptographically bound approvals & atomic consumption:** Human approval uses LangGraph `interrupt()` and `Command(resume=...)` restricted to the local CLI boundary with OS-user audit metadata. Each approval generates a unique `pending_approval_id` bound to project, thread, action ID, canonical action hash, scope revision, and expiry. Resumed execution atomically consumes the pending ID, ensuring replay protection and idempotency under LangGraph node-restart semantics.
4. **Dedicated audit sanitization & fail-closed hash chain:** The audit log is an append-only JSON Lines file with a SHA-256 hash chain and exclusive file locking. `viper.agents.audit` implements dedicated allowlist schemas and recursive sanitization (redacting tokens, cookies, auth headers, and exception traces), eliminating reliance on `logging_setup`. If audit writes fail, execution fails closed before dispatch.
5. **Fixed stub execution & runtime contracts:** M5 execution is strictly bound to `DryRunExecutor` dispatching to registered stubs; no real scanners or network sockets (TCP/UDP) exist in M5. The offline CI test suite enforces zero network calls via socket/subprocess monkeypatching, and verifies approval interrupt reachability via stub actions requiring approval.

## Consequences
- Safety policy and approval logic are 100% testable without live targets, networks, or non-deterministic LLMs.
- Scope and settings cannot be bypassed by prompt injection or graph state tampering.
- Because LangGraph restarts an interrupted node upon resume, pre-interrupt logic is strictly idempotent and consumption is atomic.
- Pinned LangGraph versions and API contract tests protect against breaking changes in `interrupt()` / `stream_events`.
- A local hash chain provides tamper evidence and internal consistency detection; cryptographic authenticity against root filesystem rewriting is deferred to M6 external anchoring.

## Alternatives considered
- **LLM self-check of scope:** Rejected; non-deterministic and easily bypassed via prompt injection.
- **Prebuilt ReAct agent without policy node:** Rejected; lacks deterministic authorization and human approval checkpoints.
- **PostgreSQL audit table in M5:** Deferred; file-based JSON Lines with hash chaining satisfies M5 requirements at $0 cost and zero Docker/DB dependencies until M6.
- **Relying on logging_setup for redaction:** Rejected; `logging_setup` has no sanitization pass and `Settings.redacted()` only covers typed settings.
