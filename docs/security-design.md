# Security Design

## Principles
Authorization first, default-deny, human-controlled, observable, recoverable. No unapproved live-target testing.

## Controls
1. **Authorization:** every project records the program URL, in-scope assets, exclusions, allowed/forbidden techniques, rate limits and permission evidence. Missing or ambiguous = deny.
2. **Deterministic policy:** `viper.policy` evaluates every proposed action. LLM text can never grant permission.
3. **Two enforcement points:** orchestrator (local) and execution API (cloud VM). Network egress is also allowlisted.
4. **Approvals:** explicit target, tool, parameters and expiry; recorded in the audit log.
5. **Kill switch:** `allow_active_testing` defaults to `false`. Emergency stop revokes new jobs and terminates tracked process trees, then verifies.
6. **Exclusive control:** a lock prevents human and AI driving the desktop at once; resume re-checks state.
7. **Secrets:** only in git-ignored `.env`, typed `SecretStr`, redacted in logs and `--health`. Short-lived credentials for the VM API; TLS everywhere.
8. **Plane isolation:** training, knowledge, local and execution planes do not share credentials.
9. **Evidence handling:** redact cookies, tokens and personal data in logs and reports.
10. **Training data:** permission-cleared only; never private bug-bounty reports.

## Risks to resolve before M6
- Cloud provider acceptable-use policy for scanning.
- Program rules that forbid automated scanning.
- Remote desktop and management API exposure (no public access without strong auth).
- Reliable process-tree termination on the VM.

## Testing
Policy and approval logic get unit tests first (M5), including adversarial cases (prompt injection in scope documents, out-of-scope redirects, expired approvals).
