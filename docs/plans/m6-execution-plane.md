# M6 specification: Cloud Kali execution plane (headless-first)

Status: Proposed Draft (2026-11-07). Docs, configuration, and execution plane design.
Roadmap definition of done: Remote execution client and VM API server execute approved actions on an on-demand cloud Kali VM over an IAP tunnel with watch, pause, and emergency-stop controls; mock-first testing ensures zero accidental network egress.

---

## 1. Scope and runtime contracts

- **In scope:**
  - Remote execution client (`viper.execution.remote.RemoteExecutor`) implementing the `Executor` protocol.
  - VM execution server (`vmapi`) providing an authenticated, localhost-only FastAPI REST/SSE service.
  - Fail-safe executor selector (`viper.execution.factory.make_executor`) strictly defaulting to `DryRunExecutor` unless three independent safety conditions are met.
  - Shared API contract (Exec API v1) defining job dispatch, status querying, live stdout streaming, job pausing, and emergency termination.
  - Exclusive-control concurrency lock (`viper.execution.control.ExclusiveControl`) built on `ClaimStore` (`SqliteClaims`) preventing simultaneous agent and human operation.
  - Network isolation architecture utilizing Google Cloud Identity-Aware Proxy (IAP) SSH tunneling (zero public IP, zero public ingress).
  - Transport Layer Security (TLS) with pinned CA certificate verification and constant-time bearer token authentication.
  - Dual-layer egress target allowlist enforced client-side and server-side.
  - Process-group lifecycle management (`os.setsid`) enabling reliable process-tree suspension (`SIGSTOP`) and emergency termination (`SIGKILL`).
  - Allowlisted scanner tools: `nmap` and `nuclei` restricted to non-destructive argument sets.
  - Authorized lab test scope targeting `scanme.nmap.org`.
  - Operator CLI verbs: `viper exec watch`, `viper exec pause`, `viper exec stop`, `viper exec takeover`.

- **Out of scope (M7+):**
  - Graphical desktop takeover via noVNC (deferred to a later M6 slice or M7).
  - Multi-tenant execution plane or concurrent multi-job VM dispatch.
  - Target network egress outside `scanme.nmap.org`.
  - Destructive, intrusive, or exploitation tools (e.g. `sqlmap`, Metasploit, brute-forcers; `RiskLevel.INTRUSIVE` remains permanently denied).
  - External cryptographic audit-head anchoring (e.g. Sigstore/Rekor, RFC 3161 TSA; deferred while local hash chain is maintained).

- **Execution invariant:**
  Under default configuration, Viper never dispatches network traffic to an external target. Real remote execution is structurally impossible without explicitly setting `allow_active_testing = True`, configuring `exec_api_url`, and providing valid authentication tokens. Even when active testing is enabled, actions must pass both policy evaluation points, match the client-side egress allowlist, match the server-side target allowlist, and be authorized by human approval.

- **Runtime contracts:**
  - *Offline CI / Mock contract:* The automated test suite executes completely offline without external network dependencies. `RemoteExecutor` is tested using HTTP client mock adapters (`httpx` / `respx`), and the `vmapi` server is tested against simulated benign commands (`sleep`, `python`) using `TestClient`. Sockets and external subprocesses in unit tests remain strictly isolated.
  - *Local development contract:* Developers work locally using dry-run stubs or mock servers.
  - *Gated live execution contract:* A live cloud Kali VM is provisioned on-demand, accessed strictly via an authenticated IAP tunnel, tested exclusively against `scanme.nmap.org`, and immediately stopped after test execution to prevent ongoing compute billing.

---

## 2. Module map & components

| Package / Directory | File / Component | Responsibility |
|---|---|---|
| `viper.execution` | `remote.py` (`RemoteExecutor`) | Client that POSTs approved actions to VM API, manages SSE streams, and translates responses into `DryRunResult`-compatible output. |
| `viper.execution` | `factory.py` (`make_executor`) | Fail-safe executor selector returning `DryRunExecutor` unless 3 safety conditions are satisfied. |
| `viper.execution` | `control.py` (`ExclusiveControl`) | Concurrency control built on `SqliteClaims` ensuring mutual exclusion between agent and human. |
| `vmapi` | `app.py` | FastAPI application defining Exec API v1 routes bound strictly to `127.0.0.1`. |
| `vmapi` | `auth.py` | Constant-time bearer token validation middleware and security dependencies. |
| `vmapi` | `jobs.py` | In-memory job state tracker, status management, and event-stream queueing. |
| `vmapi` | `toolrunner.py` | Process-group spawner (`start_new_session=True`), argument validator, pause (`SIGSTOP`), and stop (`SIGKILL`). |
| `projects/lab-scanme` | `scope.yaml` | Authoritative YAML scope file for `scanme.nmap.org` with strict Pydantic validation. |
| `docs/plans` | `m6-execution-plane.md` | Architecture specification, API contract, and security controls (this document). |
| `docs/plans` | `m6-gcloud-vm-setup.md` | Operator setup and teardown runbook for headless GCP Kali VM over IAP. |
| `docs/adr` | `0009-execution-plane.md` | Architecture Decision Record recording M6 execution plane decisions. |

---

## 3. Execution-plane architecture & state flow

### System Architecture Diagram

```
+-----------------------------------------------------------------------------------------+
| Local Workstation (Windows Orchestrator)                                                |
|                                                                                         |
|  +--------------------+      +-----------------------+      +------------------------+  |
|  | LangGraph Engine   | ---> | Policy Engine         | ---> | Approval Checkpoint    |  |
|  | (Agent Plan)       |      | (1st Enforcement Pt)  |      | (Human Resume)         |  |
|  +--------------------+      +-----------------------+      +------------------------+  |
|                                                                          |              |
|  +-----------------------------------------------------------------------+              |
|  |                                                                                      |
|  v                                                                                      |
|  +--------------------+      +-----------------------+      +------------------------+  |
|  | execute Node       | ---> | make_executor()       | ---> | RemoteExecutor         |  |
|  | (2nd Enforce Reval)|      | (Fail-Safe 3-Check)   |      | (Client Target Check)  |  |
|  +--------------------+      +-----------------------+      +------------------------+  |
|                                                                          |              |
|                                                                          | POST /jobs   |
|                                                                          v              |
|                                                              +-----------------------+  |
|                                                              | Local IAP Port Forward|  |
|                                                              | localhost:8443        |  |
+--------------------------------------------------------------+-----------------------+--+
                                                                           |
                                  Google Cloud IAP Encrypted Tunnel        |
                                  (No Public IP, TCP:22 -> Localhost)      v
+-----------------------------------------------------------------------------------------+
| Google Cloud VM: viper-kali-lab (Spot e2-medium, 127.0.0.1:8443 only)                   |
|                                                                                         |
|  +-----------------------------------------------------------------------------------+  |
|  | vmapi (FastAPI Server under systemd)                                              |  |
|  |                                                                                   |  |
|  |  +-------------------+    +--------------------+    +--------------------------+  |  |
|  |  | Bearer Auth Check | -> | Arg/Target Check   | -> | Process Group Spawner    |  |  |
|  |  | (Timing-safe token|    | (Strict Allowlist) |    | (setsid / killpg)        |  |  |
|  |  +-------------------+    +--------------------+    +--------------------------+  |  |
|  |                                                                  |                |  |
|  |                                              Subprocess PGID     v                |  |
|  |                                              +---------------------------------+  |  |
|  |                                              | Tool: nmap / nuclei             |  |  |
|  |                                              | Target: scanme.nmap.org         |  |  |
|  |                                              +---------------------------------+  |  |
|  +-----------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------+
```

### Dispatch Lifecycle
1. **Plan & Gate:** The agent proposes an `Action`. The policy engine evaluates it against authoritative `Scope` loaded from `projects/lab-scanme/scope.yaml`. `RiskLevel.ACTIVE` actions require human approval.
2. **Approval Checkpoint:** The thread pauses. The operator inspects the proposed action details and issues `viper agent resume --decision ALLOW`.
3. **Pre-dispatch Re-evaluation (Second Enforcement Point):** LangGraph invokes the `execute` node. The node independently re-verifies policy against current scope and settings, checks approval validity, and claims the single-use approval token.
4. **Selector Execution:** `make_executor(settings, registry)` evaluates the 3 fail-safe conditions. If satisfied, it instantiates `RemoteExecutor`; otherwise it returns `DryRunExecutor`.
5. **Exclusive Control Check:** `RemoteExecutor` checks `ExclusiveControl` to ensure a human operator does not currently hold a manual lock on the execution plane.
6. **Client-side Egress Verification:** `RemoteExecutor` normalizes the action target and verifies it is present in `settings.exec_egress_allowlist`.
7. **API Dispatch:** `RemoteExecutor` submits `POST /jobs` to `https://localhost:8443/jobs` with `Authorization: Bearer <token>` through the IAP tunnel.
8. **Server Verification & Isolation:** `vmapi` verifies the bearer token, validates that the tool and arguments conform to strict argument allowlists, verifies the target is permitted, and spawns the tool in a dedicated process group (`start_new_session=True`).
9. **Streaming & Completion:** Output is captured and buffered. The orchestrator streams logs via `GET /jobs/{id}/stream`. When execution terminates, the server records the exit code and final status.
10. **Result Normalization:** `RemoteExecutor` constructs a result object matching `DryRunResult` (`tool`, `args`, `summary`, `simulated=False`) so upstream LangGraph state and audit logging operate without divergence.

---

## 4. SHARED CONTRACT — Exec API v1 Specification

The Exec API v1 defines the explicit HTTP contract between the orchestrator client (`RemoteExecutor`) and the VM server (`vmapi`).

### Transport & Authentication
- **Base URL:** `https://127.0.0.1:8443` (tunneled locally via IAP). The server never listens on external interfaces (`0.0.0.0`).
- **TLS:** HTTPS enforced. Self-signed or private CA certificate pinned on the client via `settings.exec_api_ca_cert`.
- **Headers:** `Authorization: Bearer <exec_api_token>` required on every endpoint.
- **Error Codes:**
  - `401 Unauthorized`: Token missing, malformed, or invalid (timing-safe check).
  - `422 Unprocessable Entity`: Tool, argument, or target rejected by allowlists.
  - `404 Not Found`: Requested `job_id` does not exist.
  - `409 Conflict`: `job_id` already exists or invalid state transition.

### Endpoints

#### 1. `GET /health`
Verifies server reachability, authentication, and installed scanner tool status.
- **Request:** Empty body.
- **Response `200 OK`:**
  ```json
  {
    "status": "ok",
    "tools": ["nmap", "nuclei"]
  }
  ```

#### 2. `POST /jobs`
Submits an approved security action for execution.
- **Request Body:**
  ```json
  {
    "job_id": "act-01jc...",
    "tool": "nmap",
    "args": {
      "target": "scanme.nmap.org",
      "ports": "80,443",
      "timing": "-T3"
    },
    "target": "scanme.nmap.org"
  }
  ```
- **Response `201 Created`:**
  ```json
  {
    "job_id": "act-01jc...",
    "state": "running"
  }
  ```
- **Response `422 Unprocessable Entity`:**
  ```json
  {
    "error": "Validation failed",
    "detail": "Argument '-oN' is forbidden"
  }
  ```

#### 3. `GET /jobs/{job_id}`
Retrieves execution status, state, and exit code.
- **Response `200 OK`:**
  ```json
  {
    "job_id": "act-01jc...",
    "state": "running",
    "exit_code": null
  }
  ```
  Valid states: `"running"`, `"paused"`, `"done"`, `"killed"`, `"failed"`.

#### 4. `GET /jobs/{job_id}/stream`
Streams live process stdout/stderr using Server-Sent Events (SSE).
- **Response Header:** `Content-Type: text/event-stream; charset=utf-8`
- **Stream Format:** One line of process output per `data:` frame:
  ```
  data: Starting Nmap 7.94 ( https://nmap.org ) at 2026-11-07 18:00 UTC
  
  data: Nmap scan report for scanme.nmap.org (45.33.32.156)
  
  data: Host is up (0.072s latency).
  
  data: PORT    STATE SERVICE
  
  data: 80/tcp  open  http
  
  data: 443/tcp open  https
  
  event: done
  data: {"exit_code": 0}
  ```

#### 5. `POST /jobs/{job_id}/pause`
Suspends execution of the running process tree.
- **Mechanism:** Sends `signal.SIGSTOP` to the job's process group (`os.killpg(pgid, signal.SIGSTOP)`).
- **Response `200 OK`:**
  ```json
  {
    "job_id": "act-01jc...",
    "state": "paused"
  }
  ```

#### 6. `POST /jobs/{job_id}/stop`
Emergency termination of the process tree.
- **Mechanism:** Sends `signal.SIGKILL` to the entire process group (`os.killpg(pgid, signal.SIGKILL)`), waits for process exit, and confirms termination.
- **Response `200 OK`:**
  ```json
  {
    "job_id": "act-01jc...",
    "state": "killed"
  }
  ```

---

## 5. Safety, authentication & isolation controls

### 1. Fail-Safe Executor Selector
The factory function `viper.execution.factory.make_executor(settings, registry)` implements a strict fail-safe gate. It returns `DryRunExecutor` **unless all three conditions are simultaneously met**:
1. `settings.allow_active_testing is True` (explicit operator opt-in).
2. `settings.exec_api_url` is configured (non-empty string, e.g. `https://localhost:8443`).
3. `settings.exec_api_token` and `settings.exec_api_ca_cert` are present, non-empty, and reference an existing CA certificate.

If any condition evaluates to `False`, the selector safely falls back to `DryRunExecutor`. This guarantees that existing unit tests, dry-run development, and default configurations cannot trigger live remote calls.

### 2. Exclusive-Control Concurrency Lock
To prevent conflicts between automated agent runs and human operators, `viper.execution.control.ExclusiveControl` provides an exclusive claim model backed by `SqliteClaims`.
- Keys: `control:<project_id>:<vm_id>`.
- When an operator initiates manual takeover via `viper exec takeover --project <id>`, an exclusive claim is registered.
- `RemoteExecutor` asserts that no human claim exists before dispatching a job. If held, dispatch raises `ExclusiveControlConflict` and aborts.
- Releasing the lock re-verifies that any dangling VM processes are inspected or cleared before control is returned to automated execution.

### 3. Zero Public Ingress Architecture (GCP IAP)
- The execution VM is provisioned with `--no-address` (no external IPv4 or IPv6 address).
- No firewall rules permit ingress from `0.0.0.0/0`.
- The sole ingress firewall rule allows Google Cloud IAP IP space (`35.235.240.0/20`) on TCP port 22.
- The operator workstation opens an encrypted, IAM-authenticated tunnel using `gcloud compute start-iap-tunnel viper-kali-lab 8443 --local-host-port=localhost:8443`.
- `vmapi` on the VM binds exclusively to loopback `127.0.0.1:8443`.
- The execution API is completely invisible and unreachable from the public internet.

### 4. Mutual Authentication & Secrets Handling
- **TLS Certificate Pinning:** `RemoteExecutor` enforces HTTPS certificate validation using the certificate pinned at `VIPER_EXEC_API_CA_CERT`.
- **Bearer Token Security:** The shared secret is generated on the VM using `openssl rand -hex 32` and stored on the VM in `/etc/viper/vmapi.env` with file permissions `0600`.
- **Zero Exposure:** `VIPER_EXEC_API_TOKEN` is loaded into Viper as a Pydantic `SecretStr`. It is masked from logs, excluded from serialization, and redacted in debug dumps.
- **Timing-Safe Comparison:** `vmapi.auth` utilizes `secrets.compare_digest` to prevent timing side-channel attacks during token validation.

### 5. Dual-Layer Egress Target Allowlist
1. **Client-side Allowlist:** `RemoteExecutor` normalizes the action target and verifies it against `settings.exec_egress_allowlist`. Any target not explicitly enumerated is refused before network dispatch.
2. **Server-side Allowlist:** `vmapi.toolrunner` re-verifies that the target matches its configured target whitelist (`scanme.nmap.org`). If an unauthorized target is received, the server rejects the request with HTTP `422`.

### 6. Process-Group Emergency Stop
Individual tool executions frequently spawn subshells or child utilities.
- When `vmapi` spawns a job, it sets `start_new_session=True` (or `preexec_fn=os.setsid`), establishing a new process group with `PGID = PID`.
- Emergency stop (`POST /jobs/{id}/stop`) invokes `os.killpg(pgid, signal.SIGKILL)`.
- The server performs `os.waitpid` and verifies `/proc/{pid}` to confirm that all child processes in the process tree have terminated before returning `200 OK`.

### 7. Tool & Argument Hardening
To prevent shell metacharacter injection and privilege escalation, `vmapi` enforces strict parameter parsing:
- No shell invocation (`shell=False` required).
- Disallow dangerous arguments: output file redirection (`-oN`, `-oX`, `-oG`), script execution flags that allow arbitrary code (`--script=external-url`, `--script=arbitrary-lua`), and argument injection.
- Allowlisted tool arguments for Round 1:
  - `nmap`: Target specifications, benign timing templates (`-T1` through `-T4`), basic port filters (`-p`), service detection (`-sV`), and passive/ping modes (`-Pn`, `-sn`).
  - `nuclei`: Specific benign template tags against verified targets, rate limiters (`-rl`), and silent output.
- Any unrecognized argument or shell metacharacter (`|`, `&`, `;`, `$`, `>`, `<`, `` ` ``) triggers immediate HTTP `422` rejection.

### 8. External Audit Anchoring Limitation
In M6, audit records continue to be written to the local SHA-256 hash-chained JSON Lines log (`data/audit/{project_id}.jsonl`). External cryptographic anchoring (such as public Rekor transparency log submissions or RFC 3161 timestamping) is deferred. While the local hash chain detects tampering, truncation, and internal inconsistency, it does not defend against an adversary with host root privileges rewriting the chain.

---

## 6. RemoteExecutor client & vmapi server designs

### `RemoteExecutor` Client (`src/viper/execution/remote.py`)
```python
class RemoteExecutor:
    """Dispatches approved actions to the remote VM API over an IAP tunnel."""

    def __init__(self, settings: Settings, claims: ClaimStore) -> None:
        self._url = settings.exec_api_url.rstrip("/")
        self._token = settings.exec_api_token.get_secret_value()
        self._ca_cert = str(settings.exec_api_ca_cert)
        self._egress_allowlist = set(settings.exec_egress_allowlist)
        self._claims = claims

    def execute(self, action: Action) -> DryRunResult:
        # 1. Target egress check
        target = action.args.get("target")
        if not target or target not in self._egress_allowlist:
            raise PermissionError(f"Target {target} not in client egress allowlist")

        # 2. Assert exclusive control
        # 3. HTTP POST /jobs over httpx with verify=self._ca_cert
        # 4. Stream or poll until completion
        # 5. Return DryRunResult(tool=action.tool_name, args=action.args, summary=output, simulated=False)
```

### `vmapi` Server Architecture (`vmapi/`)
```
vmapi/
├── app.py             # FastAPI entrypoint, route handlers, error handlers
├── auth.py            # Bearer token validation with secrets.compare_digest
├── jobs.py            # Job state store, dataclasses, status enum
├── toolrunner.py      # Process spawner (start_new_session=True), arg checks, SIGSTOP/SIGKILL
├── requirements.txt   # fastapi>=0.110, uvicorn>=0.28, pydantic>=2.0
└── tests/
    └── test_vmapi.py  # Unit tests with TestClient and mock subprocesses
```

---

## 7. Test strategy (mock first)

Testing follows a strict mock-first methodology to guarantee safety in CI and development environments.

### 1. Unit & Offline Tests (No VM, Runs in CI)
- **Selector Tests (`tests/test_remote_executor.py`):**
  - Verify `make_executor` returns `DryRunExecutor` when `allow_active_testing=False`.
  - Verify `make_executor` returns `DryRunExecutor` when `exec_api_url` is missing.
  - Verify `make_executor` returns `DryRunExecutor` when token/cert is missing.
  - Verify `make_executor` returns `RemoteExecutor` only when all 3 flags are valid.
- **Client Mock Tests (`tests/test_remote_executor.py`):**
  - Use `httpx.Response` mock / `respx` to test `RemoteExecutor.execute()` with 201/200 flow.
  - Test client-side egress rejection when target is outside allowlist (raises without sending HTTP).
  - Test streaming output parser and result translation.
- **Server Offline Tests (`vmapi/tests/test_vmapi.py`):**
  - Test with FastAPI `TestClient`.
  - Validate 401 response on missing or invalid Bearer token.
  - Validate 422 response on unauthorized target or unapproved tool.
  - Validate 422 response on shell injection characters in arguments.
  - Validate process-group lifecycle using a harmless mock subprocess (`python -c "import time; time.sleep(10)"`).
  - Validate `/pause` issues `SIGSTOP` and `/stop` issues `SIGKILL`, verifying process tree disappearance.

### 2. Adversarial & Safety Boundary Tests
- Model proposes argument containing command separators (e.g. `scanme.nmap.org; cat /etc/passwd`). Assert server rejects with 422.
- Tool attempts to pass output file flags (`-oN /tmp/owned`). Assert rejection.
- Out-of-scope target supplied to `RemoteExecutor`. Assert refused client-side before socket creation.
- Concurrent human lock acquisition. Assert agent dispatch fails closed with `ExclusiveControlConflict`.

### 3. Gated Live Verification (Target: `scanme.nmap.org`)
Follow the steps in `docs/plans/m6-gcloud-vm-setup.md`:
1. Provision spot VM in GCP with `--no-address`.
2. Start IAP tunnel locally.
3. Configure `.env` with short-lived token and local cert.
4. Execute `viper agent run --scope projects/lab-scanme/scope.yaml --plan projects/lab-scanme/plan.json --thread lab1`.
5. Execute `viper agent resume ... --decision ALLOW`.
6. Stream scan output with `viper exec watch --thread lab1`.
7. Verify job cancellation with `viper exec stop --thread lab1`.
8. Verify intact audit log with `viper audit verify --project lab-scanme`.
9. Stop VM to cap cost.

---

## 8. Milestones (PR-sized)

1. **M6-1: Contract & Mock Infrastructure (Current)**
   - Authoritative M6 architecture specification (`docs/plans/m6-execution-plane.md`).
   - Operator GCP VM guide (`docs/plans/m6-gcloud-vm-setup.md`).
   - Architectural Decision Record (`docs/adr/0009-execution-plane.md`).
   - Authoritative scope for `scanme.nmap.org` (`projects/lab-scanme/scope.yaml`).

2. **M6-2: Remote Client & Fail-Safe Selector (`lane-A-m6`)**
   - Implement `RemoteExecutor` in `src/viper/execution/remote.py`.
   - Implement `make_executor` selector in `src/viper/execution/factory.py`.
   - Test client with mocked responses and assert selector failsafe behavior (`tests/test_remote_executor.py`).

3. **M6-3: VM Execution API Server (`lane-B-m6`)**
   - Implement FastAPI server under `vmapi/` (`app.py`, `auth.py`, `jobs.py`, `toolrunner.py`).
   - Process group isolation, signal-based pause/stop, argument allowlisting.
   - Comprehensive test suite under `vmapi/tests/test_vmapi.py`.

4. **M6-4: Orchestrator Wiring & Exclusive Control (`coordinator`)**
   - Inject `executor` into `Deps` and update `runner._graph`.
   - Implement exclusive-control claim locks (`src/viper/execution/control.py`).
   - Wire CLI verbs (`viper exec watch`, `viper exec pause`, `viper exec stop`, `viper exec takeover`).

5. **M6-5: Live Verification & Teardown Runbook**
   - Execute gated live run against `scanme.nmap.org`.
   - Validate audit log chain.
   - Verify cloud teardown and cost control.

---

## 9. Resolved design decisions

1. **Headless Execution API First:** GUI desktop takeover (noVNC) is deferred. M6 focuses entirely on headless API dispatch, live stdout streaming, and process controls.
2. **Zero Public Ingress via IAP Tunneling:** The Kali VM has no external IP address. Communication occurs exclusively over Google Cloud IAP SSH port forwarding to localhost `127.0.0.1:8443`.
3. **Three-Condition Fail-Safe Selector:** Live dispatch is impossible unless `allow_active_testing=True`, `exec_api_url` is configured, and a valid token/cert pair is provided. Default behavior remains 100% dry-run.
4. **Restricted Lab Target (`scanme.nmap.org`):** Scanning is strictly constrained to Nmap's officially authorized scan-test host.
5. **Process-Group Emergency Stop:** Tools are spawned in dedicated process groups to ensure `SIGKILL` cleanly terminates the entire process tree without leaving orphaned scanner tasks.
6. **External Audit Anchoring Deferred:** External notarization/timestamping of audit log heads is deferred to M7 while local hash chains provide internal tamper detection.
