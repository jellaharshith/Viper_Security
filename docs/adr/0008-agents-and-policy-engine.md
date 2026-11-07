# ADR 0008: LangGraph agents with a deterministic policy engine

Status: Proposed (2026-11-07)

## Context
M5 adds agents that can propose security-testing actions. The LLM is not trustworthy for authorization
(prompt injection, hallucinated scope). See docs/security-design.md and docs/plans/m5-agents-policy.md.

## Decision
1. Agents are a LangGraph `StateGraph`; the LLM only proposes `Action` objects.
2. `viper.policy.evaluate` is a pure, deny-by-default function and the sole source of ALLOW / REQUIRE_APPROVAL / DENY.
   Active and intrusive risk levels are denied while `allow_active_testing` is false.
3. Human approval uses LangGraph `interrupt()` / `Command(resume=...)` with a checkpointer. Approvals are bound to an action
   hash, expire, and are single-use. `execute` re-verifies independently of graph routing.
4. The audit log is append-only JSON Lines with a SHA-256 hash chain; a verifier detects tampering.
5. M5 tools are stubs/dry-run only: no network I/O and no tool execution. Real execution is M6.

## Consequences
- Safety logic is testable without an LLM or network, and the graph can change without weakening policy.
- Resume restarts the interrupted node, so pre-interrupt code must be idempotent.
- LangGraph's streaming API (`stream_events` v3) is new: pin versions and keep a contract test.
- A local hash chain gives tamper evidence, not authenticity; external anchoring is deferred to M6.

## Alternatives considered
LLM self-check of scope (rejected: not deterministic); a prebuilt ReAct agent without a policy node (rejected: no
enforcement point); a database audit table now (deferred: PostgreSQL arrives in M6).
