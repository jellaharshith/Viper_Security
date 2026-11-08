# Lab Scope: scanme.nmap.org

This directory defines the authoritative engagement scope for testing Viper against the official Nmap test service (`scanme.nmap.org`).

## Target Authorization & Rules of Engagement

- **Target Host:** `scanme.nmap.org` (IPv4: `45.33.32.156`, IPv6: `2600:3c01::f03c:91ff:fe18:bb2f`)
- **Authorization Reference:** Official authorization provided by Fyodor / The Nmap Project at [https://scanme.nmap.org/](https://scanme.nmap.org/):
  > *"Hello, and welcome to Scanme.Nmap.Org, a service provided by the Nmap Security Scanner Project and Insecure.Org. We set up this machine to help folks learn about Nmap and also to test and make sure that their Nmap installation (or internet connection) is working properly. You are authorized to scan this machine with Nmap or other network scanners. Try not to hammer on the server too hard. A few scans a day is fine, but don't scan for spam or attempt to exploit vulnerabilities on this host."*
- **Program URL:** `https://scanme.nmap.org/`
- **Scope File:** [`scope.yaml`](scope.yaml)
- **Forbidden Techniques:** `INTRUSIVE` (Exploitation, denial-of-service, brute-forcing, high-frequency scanning).

## Testing Invariants in M7

1. **Strict Target Restriction:** All test plans, action dispatches, and finding validations must target `scanme.nmap.org` exclusively. Any action addressing other IPs or domain names is refused by client-side egress validation and server-side allowlists.
2. **Benign Scanning Only:** Scans are limited to TCP port discovery (`nmap`) and benign, passive vulnerability/technology detection (`nuclei`).
3. **Confirmed vs. Hypothesis Findings:**
   - Standard open ports (e.g. 22/tcp OpenSSH, 80/tcp Apache) parsed from Nmap output are classified as `confidence="confirmed"` with severity `info`.
   - Cleartext services (if any) escalate to severity `low`.
   - Ambiguous scanner states (`open|filtered`), model deductions, or foreign-host matches are classified as `confidence="hypothesis"`.
4. **Tool Output Capture:** `RemoteExecutor` captures raw scanner stdout from the remote VM stream endpoint up to a 1 MiB safety ceiling (`DryRunResult.output`, `DryRunResult.truncated`).
5. **Audit Traceability & Anchoring (Evidence Events v2):**
   - Real tool dispatches log operational intent as `tool_dispatch` before execution, and execution outcome with an output SHA-256 digest as `tool_result` after execution. The legacy event `tool_executed` does not exist.
   - Findings are re-derived at analysis and report time from digest-verified output.
   - Completed findings emit `findings_generated`, and final report generation emits `report_generated`.
   - CLI audit anchoring (`viper audit anchor --project lab-scanme`) records mock receipts in `data/audit/lab-scanme.anchors.jsonl` with event `audit_anchored`. Note: M7 CLI anchoring is mock-only.

## Operator Execution Workflow

```bash
# 1. Propose and run a test plan (deterministic JSON or opt-in LLM planner)
viper agent run --scope projects/lab-scanme/scope.yaml --thread lab1 --plan plans/scanme.json
# OR with the opt-in LLM planner (requires non-empty request, max 8 actions):
viper agent run --scope projects/lab-scanme/scope.yaml --thread lab1 --llm --request "scan scanme.nmap.org for open web ports"

# 2. Inspect pending action and resume at approval checkpoint
viper agent resume --scope projects/lab-scanme/scope.yaml --thread lab1 --decision ALLOW

# 3. View the persisted Markdown report (exclusive creation, terminal-safe)
viper report --thread lab1
# (Saved to data/reports/lab1.md)

# 4. Anchor the audit log head (mock provider)
viper audit anchor --project lab-scanme

# 5. Verify audit log integrity, anchor coverage, and anchor verdicts
viper audit verify --project lab-scanme
```
