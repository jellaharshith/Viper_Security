# M5 Agent & Policy Engine: Open Design Decisions

This document presents the 5 open design questions for milestone **M5 (LangGraph agents + deterministic policy engine)**. Each question outlines the context, the available options, our recommended choice, and the associated trade-offs in plain language to guide user decision-making.

---

## 1. Checkpoint Persistence: SQLite vs In-Memory

### Context
When the agent encounters an action requiring human authorization, LangGraph pauses execution using an `interrupt()`. To resume the graph later from the command line (e.g. `viper agent resume --thread <id> --approval-id <id>`), the graph's execution state must be saved to disk or kept in memory.

### Options
- **Option A (Recommended): Local SQLite database (`SqliteSaver`).** Paused thread states are stored in a local SQLite file (e.g. `data/checkpoints.db`).
- **Option B: In-memory only (`InMemorySaver`).** Paused thread states exist only in the RAM of the running Python process.
- **Option C: Flat JSON files per thread.** Paused thread states are dumped as individual JSON files under `data/threads/`.

### Recommendation
**Option A (`SqliteSaver` for CLI, `InMemorySaver` for unit tests).**
This enables a true command-line workflow: an operator can start an agent run, pause for human approval, close the terminal or log off, and resume later from another terminal. In-memory checkpoints are retained as the fast, zero-footprint option for automated pytest suites.

### Trade-offs
| Consideration | Option A: SQLite (Recommended) | Option B: In-Memory | Option C: Flat JSON Files |
|---|---|---|---|
| **CLI Usability** | High: pause in one process, resume in another | Low: requires continuous interactive session | Medium: human-readable files |
| **Dependencies** | Requires `langgraph-checkpoint-sqlite` | Zero dependencies (`langgraph-checkpoint`) | Zero dependencies |
| **Concurrency / Safety** | Handled natively by SQLite transactions | Process-bound; lost on crash or terminal close | Prone to file-locking races and corruption |
| **Complexity** | Low: standard LangGraph checkpointer pattern | Minimal | High: hand-rolled state serialization |

---

## 2. Approver Identity: Local OS Username vs Manual Prompt

### Context
When an operator grants or denies an approval checkpoint (`viper agent resume --decision ALLOW`), the audit log records who made the decision. In M5, all actions execute locally and all target tools are dry-run stubs; there is no cloud user directory or central identity provider.

### Options
- **Option A (Recommended): Automatic local OS user (`getpass.getuser()`).** The CLI automatically captures the current operating system login (e.g. `alice`, `security-admin`) as audit metadata.
- **Option B: Explicit CLI flag (`--approver <name>`).** The operator supplies a free-form name or email address, with fallback to the OS username if omitted.
- **Option C: Mandatory interactive confirmation prompt.** The CLI stops and interactively asks: *"Enter your name / operator ID:"*.

### Recommendation
**Option A (Automatic local OS user).**
Capturing `getpass.getuser()` provides reliable, non-spoofable local metadata with zero operator friction. In M5, this is audit metadata, not cryptographically verified authentication. Operators can optionally pass an optional `--reason` or `--ticket` flag to document organizational change-ticket references.

### Trade-offs
| Consideration | Option A: OS User (Recommended) | Option B: CLI Flag | Option C: Interactive Prompt |
|---|---|---|---|
| **Operator Friction** | Zero: command runs immediately | Low: optional flag | High: pauses every CLI resume |
| **Shared Machines** | Shows workstation account (e.g. `secops`) | Allows individual names | Allows individual names |
| **Spoofability** | Cannot be altered via command flag | Trivial to type any name | Trivial to type any name |
| **Automation & CI** | Scriptable without interactive prompts | Scriptable | Breaks automated resume scripts |

---

## 3. Scope Specification: YAML vs JSON

### Context
Every security testing project requires a defined scope document specifying in-scope targets (hosts, domains, CIDR ranges), exclusions (which always override inclusions), allowed/forbidden testing techniques, rate limits, and permission evidence. The policy engine evaluates proposed actions against this document.

### Options
- **Option A (Recommended): YAML file per project (`projects/{project_id}/scope.yaml`).** Strict Pydantic schema validation with inline comments enabled.
- **Option B: JSON file per project (`projects/{project_id}/scope.json`).** Strict schema validation, standard library parser, no comments.
- **Option C: Command-line flags only (`--in-scope`, `--out-of-scope`).** Scope passed dynamically as CLI arguments on each invocation.

### Recommendation
**Option A (YAML per project with strict schema).**
Security scope files are human-authored and benefit greatly from comments explaining *why* specific systems are out of scope (e.g. `# Production payment gateway - testing strictly forbidden by client`). The file is parsed into a Pydantic model and hashed into a canonical JSON SHA-256 digest (`scope_revision`) to detect any mid-engagement scope modifications.

### Trade-offs
| Consideration | Option A: YAML (Recommended) | Option B: JSON | Option C: CLI Flags |
|---|---|---|---|
| **Human Readability** | High: clean syntax, supports comments | Medium: rigid syntax, no comments | Low: unwieldy for multi-domain targets |
| **Risk of Human Error** | Indentation errors caught by validator | Missing comma / quote errors | Easy to omit exclusions on command line |
| **Integrity & Hashing** | Converted to canonical JSON for hashing | Directly hashable | Difficult to track revision history |
| **Dependencies** | Requires PyYAML (already standard in Python) | Standard library only | None |

---

## 4. Policy Approval Threshold: ACTIVE Only vs PASSIVE + ACTIVE

### Context
The policy engine categorizes actions into four risk tiers:
- `READ`: Knowledge-base searches, scope lookups, local documentation.
- `PASSIVE`: Dry-run planning, simulated reconnaissance on in-scope targets.
- `ACTIVE`: Simulated testing sending traffic to target systems (in M5, dry-run only; real scans blocked by `allow_active_testing=False`).
- `INTRUSIVE`: Exploitation, password cracking (always blocked in M5).

### Options
- **Option A (Recommended): Require human approval for `ACTIVE` actions only.** `READ` and verified in-scope `PASSIVE` dry-run actions execute automatically.
- **Option B: Require human approval for both `PASSIVE` and `ACTIVE` actions.** Only local `READ` actions are automated.
- **Option C: Configurable threshold per project scope (`approval_level: PASSIVE | ACTIVE`).**

### Recommendation
**Option A (Approval required for `ACTIVE` actions only).**
Auto-allowing `READ` and verified in-scope `PASSIVE` actions allows the agent to formulate plans and perform dry-run feasibility checks without human interruption. Human review is reserved for the point of consequence (when an active action is about to be staged). In M5, active actions are denied by default (`allow_active_testing=False`), and approval mechanics are exercised safely using approval-required test stubs.

### Trade-offs
| Consideration | Option A: ACTIVE Only (Recommended) | Option B: PASSIVE + ACTIVE | Option C: Configurable Threshold |
|---|---|---|---|
| **Operator Fatigue** | Low: approval requested only before active actions | High: agent pauses after every basic query | Variable based on configuration |
| **Agent Autonomy** | High: agent can research and draft complete plans | Minimal: operator must micromanage planning | Configurable |
| **Safety in M5** | 100% safe: all M5 execution uses dry-run stubs | 100% safe | 100% safe |
| **Code Complexity** | Low: clear, fixed risk-level mapping | Low: fixed mapping | Higher: policy rules depend on scope config |

---

## 5. Audit Log Organization: Central Data Directory vs Per-Project Folder

### Context
All agent decisions, policy gate results, human approvals, and tool executions must be appended to a tamper-evident audit log structured as a JSON Lines file with a SHA-256 hash chain (`seq`, `ts`, `event`, `action_hash`, `prev_hash`, `hash`).

### Options
- **Option A (Recommended): Centralized directory (`data/audit/{project_id}.jsonl`).** Audit logs stored centrally under `data/audit/`, git-ignored by default, with configurable base path via `Settings.audit_dir`.
- **Option B: Inside each project folder (`projects/{project_id}/audit.jsonl`).** Audit log stored alongside project scope and plan files.
- **Option C: Single global monolithic file (`data/audit.jsonl`).** All events from all projects interleaved into a single log file.

### Recommendation
**Option A (Centralized `data/audit/{project_id}.jsonl`).**
Per-project files isolate hash chains, preventing lock contention between concurrent projects and ensuring that an issue in one project's chain does not affect another. Keeping them in `data/audit/` ensures runtime telemetry is cleanly separated from tracked repository assets and easily redirected to dedicated secure storage.

### Trade-offs
| Consideration | Option A: Central data/audit/ (Recommended) | Option B: In Project Folder | Option C: Global Monolithic File |
|---|---|---|---|
| **Git Safety** | High: entire `data/` folder is git-ignored | Risk of accidentally committing target logs | High: `data/` is git-ignored |
| **Chain Isolation** | Each project has an independent hash chain | Each project has an independent chain | Single chain: corruption breaks all projects |
| **Write Contention** | Low: file lock applies per project | Low: file lock applies per project | High: every concurrent run contends for lock |
| **Exportability** | Easy to archive or ship `{project_id}.jsonl` | Bundled with project files | Requires filtering and re-hashing |

---

## Summary of Recommendations

1. **Checkpoints:** Local SQLite database (`SqliteSaver`) for persistent CLI pause/resume; in-memory for unit tests.
2. **Approver Identity:** Local operating system username (`getpass.getuser()`) recorded as non-spoofable audit metadata.
3. **Scope Format:** YAML file per project with strict Pydantic validation and canonical JSON SHA-256 revision hash.
4. **Approval Threshold:** Human approval required for `ACTIVE` actions; `READ` and verified in-scope `PASSIVE` actions automated.
5. **Audit Storage:** Centralized, git-ignored `data/audit/{project_id}.jsonl` with configurable base path.
