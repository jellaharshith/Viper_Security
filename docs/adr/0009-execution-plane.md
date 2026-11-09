# ADR 0009: Cloud Kali execution plane with headless-first API and fail-safe dispatch

Status: Proposed (2026-11-07)

## Context
M5 established Viper's safety core: deterministic policy evaluation, single-use action-bound approval checkpoints, tamper-evident hash-chained audit logging, and the `DryRunExecutor` stub dispatcher. However, real security testing requires executing actual scanner tools (`nmap`, `nuclei`) against target networks.

Transitioning from simulated stubs to live execution introduces critical security risks:
- Accidental or unauthorized target egress during test runs or development.
- Public exposure of remote execution interfaces on the cloud VM.
- Runaway or uncoordinated scanner processes consuming target bandwidth or system resources.
- Concurrent conflicts between autonomous agent actions and manual operator interventions.
- Command injection or privilege escalation via untrusted scanner arguments.

See `docs/plans/m6-execution-plane.md`, `docs/plans/m6-gcloud-vm-setup.md`, and `docs/adr/0008-agents-and-policy-engine.md`.

---

## Decision

1. **Headless-first execution API:**
   Initial execution plane implementation focuses exclusively on an authenticated, headless HTTP/SSE service (`vmapi`) running under systemd on an on-demand cloud Kali VM. Graphical desktop streaming and interaction via noVNC are deferred to a subsequent milestone. Operator interactions (watch, pause, stop, takeover) occur via CLI commands consuming the headless API.

2. **Zero public ingress via GCP Identity-Aware Proxy (IAP):**
   The execution VM is created with `--no-address` (no external IPv4/IPv6 address). Ingress firewall rules permit only TCP port 22 traffic originating from Google Cloud's IAP netblock (`35.235.240.0/20`). The execution server binds strictly to loopback `127.0.0.1:8443`. Orchestrator communication is tunneled through `gcloud compute start-iap-tunnel`, guaranteeing that the execution API is never directly addressable from the public internet.

3. **Fail-safe executor selector gated on three conditions:**
   `viper.execution.factory.make_executor` defaults to `DryRunExecutor` unless all three conditions are simultaneously satisfied:
   - `settings.allow_active_testing is True` (explicit kill-switch toggle).
   - `settings.exec_api_url` is non-empty.
   - `settings.exec_api_token` and `settings.exec_api_ca_cert` are configured and reference a valid certificate.
   Default configurations, automated CI runs, and developer workstations continue to dispatch to dry-run stubs with zero external network connectivity.

4. **Restricted lab target (`scanme.nmap.org`):**
   Live active testing is restricted to Nmap's officially authorized scan-test host (`scanme.nmap.org`). The authorized scope is defined in `projects/lab-scanme/scope.yaml` with strict Pydantic validation rejecting unknown keys and establishing a deterministic SHA-256 `scope_revision`. Egress filtering is enforced both client-side in `RemoteExecutor` and server-side in `vmapi`.

5. **Process-group isolation and emergency-stop:**
   Every tool execution on the VM is spawned in an isolated process group (`start_new_session=True`). Pausing issues `SIGSTOP` to the entire process group (`os.killpg(pgid, signal.SIGSTOP)`). Emergency-stop issues `SIGKILL` to the process group (`os.killpg(pgid, signal.SIGKILL)`) and polls process status to verify that the tool and any child subshells are completely terminated before acknowledging the stop request.

6. **External audit-head anchoring still deferred:**
   Audit logs remain formatted as append-only JSON Lines with local SHA-256 hash chains (`data/audit/{project_id}.jsonl`). External cryptographic timestamping and transparency ledger anchoring (e.g. Rekor / RFC 3161 TSA) are deferred to M7. Local file locking, genesis hashing, and tail verification provide tamper evidence against unprivileged edits during M6.

7. **Strict argument allowlisting & exclusive control:**
   `vmapi` rejects shell metacharacters and output-redirection flags (`-oN`, `-oX`), permitting only safe, non-intrusive argument subsets for `nmap` and `nuclei`. Concurrency between agent automation and human intervention is enforced via `viper.execution.control.ExclusiveControl` backed by `SqliteClaims`.

---

## Consequences

- **Positive:**
  - Complete isolation: The execution VM has no public ingress attack surface.
  - Fail-safe defaults: Existing test suites and CI pipelines remain fully protected from accidental network calls without requiring special mocks.
  - Emergency control: Runaway scans can be stopped instantaneously with guaranteed process-tree termination.
  - Strict auditability: Every job dispatch, state transition, and pause/stop action is recorded in the tamper-evident audit log.
  - Cost containment: Spot e2-medium VM with auto-stop keeps operational costs under $50/month (negligible when stopped).

- **Trade-offs & Limitations:**
  - Operator workflow requires opening an IAP tunnel prior to live test execution.
  - No interactive GUI or graphical desktop feedback in this phase (headless CLI streaming only).
  - External audit anchoring remains deferred, leaving local hash chains vulnerable to malicious root modification if host integrity is compromised.

---

## Alternatives considered

- **Direct public IP with IP-whitelisted firewall rules:**
  *Rejected:* Exposes SSH and API ports to internet scanning; IP whitelisting is fragile on dynamic residential or mobile connections.

- **Local Docker container on the host machine:**
  *Rejected:* Running network scanners under Docker on Windows introduces WSL2/NAT network translation discrepancies, packet manipulation limitations, and fails to simulate a true remote Kali execution plane.

- **Immediate noVNC desktop implementation:**
  *Rejected:* Introduces substantial complexity (desktop environments, display servers, WebSockets, VNC authentication) that distracts from core execution safety, policy re-verification, and emergency-stop guarantees.

- **Single-condition executor toggle (relying solely on `allow_active_testing`):**
  *Rejected:* Insufficient defense in depth. Gating on active flag, valid API URL, and valid token/cert ensures that misconfiguration cannot inadvertently trigger live execution.

## V1 addendum: fixed live Nuclei profile (2026-11-08)

The VM replaces passive response processing with a fixed live JSONL profile:
`-jsonl -silent -nc -duc -no-interactsh -disable-redirects`, server-owned templates
via `-t`, tags `tech,exposure,misconfig`, excluded tags
`dos,fuzz,intrusive,bruteforce,rce,sqli,xss`, severities `info,low,medium`, concurrency
5, timeout 10 seconds and zero retries. The sole target is appended with `-u`;
`-rl` is a strict integer from 1 to 10 (default 1). Execution uses an argv list
without a shell and retains exact-host allowlisting and matching target fields.

`VIPER_EXEC_NUCLEI_TEMPLATES` is read only from the VM environment, defaulting to
`/opt/viper/nuclei-templates`. Invalid paths (relative, leading dash, whitespace
or control characters) refuse the job. The binary is installed at `/usr/bin/nuclei`
from a pinned GitHub release after checksum verification; templates are installed
by root and read-only to the unprivileged service. Operators control template
refreshes separately and record the installed revision.

Request arguments remain limited to `{target, rate_limit}`. Templates, tags and
severity are not request-controllable because arbitrary template selection or
profile expansion would bypass the reviewed execution boundary. `templates`,
`tags`, `severity`, `t`, `-passive` and other extra keys return 422. Tag/severity
filters depend on trusted template metadata; they do not replace template review,
scope approval or deployment egress controls. Findings use JSONL on stdout;
consumers tolerate non-JSON diagnostics from merged stderr.
