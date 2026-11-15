---
name: loop-test-quality
description: Discovery for the test-quality loop mode. Continuous verify-fix — coverage gaps, flakes, policy-engine correctness.
---

# test-quality discovery

Goal: raise suite quality — close coverage gaps, de-flake, harden the policy engine.

Sources:
1. Coverage report (`pytest --cov=viper --cov=vmapi --cov-report=term-missing`) — modules below
   target, especially `src/viper/policy/` (the safety-critical deterministic core).
2. Flaky tests (run the suite twice; diff pass/fail sets).
3. `pytest -q vmapi\tests tests` skipped tests with no tracking issue.

Each task adds or stabilizes tests for **one** module it owns. Done-condition: new/changed tests
pass deterministically across two consecutive runs AND coverage for the target module rises (or
the flake stops flaking). No production behavior change — tests only. Anything needing a
production fix to make testable → hand to ci-triage via a triage card.

Maker: `agy` or `claude` (write the tests). Checker: `codex` (runs the suite twice, confirms
determinism and the coverage delta).
