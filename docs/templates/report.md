# Viper Authorized Penetration Testing & Assessment Report

**Project ID:** `{{ project_id }}`<br>
**Thread ID:** `{{ thread_id }}`<br>
**Target:** `{{ target }}`<br>
**Assessment Date:** `{{ assessment_date }}`<br>
**Classification:** Confidential — Authorized Security Evaluation

---

## Executive Summary

Viper executed an authorized automated security assessment against the designated target environment in strict adherence to the defined engagement scope. Testing was performed using non-intrusive scanning tools (`nmap`, `nuclei`) under deterministic policy controls and human-in-the-loop approval gates.

All discovered issues are classified according to concrete evidence:
- **Confirmed Findings:** Validated vulnerabilities or verified open ports confirmed by deterministic tool responses.
- **Hypotheses:** Unconfirmed observations, speculative attack paths, or ambiguous scanner responses requiring additional investigation.

### Finding Metrics

| Severity | Confirmed | Hypotheses | Total |
|:---|:---:|:---:|:---:|
| **Critical** | {{ count_confirmed_critical }} | {{ count_hypo_critical }} | {{ total_critical }} |
| **High** | {{ count_confirmed_high }} | {{ count_hypo_high }} | {{ total_high }} |
| **Medium** | {{ count_confirmed_medium }} | {{ count_hypo_medium }} | {{ total_medium }} |
| **Low** | {{ count_confirmed_low }} | {{ count_hypo_low }} | {{ total_low }} |
| **Info** | {{ count_confirmed_info }} | {{ count_hypo_info }} | {{ total_info }} |
| **Total** | **{{ total_confirmed }}** | **{{ total_hypotheses }}** | **{{ grand_total }}** |

---

## Scope & Authorization

Testing was constrained exclusively to targets authorized in the signed engagement scope. Out-of-scope network traffic was blocked client-side and server-side.

- **Authorized Targets (`in_scope`):**
  - `{{ target }}`
- **Authorization Reference:** `{{ evidence_ref }}`
- **Program / Scope URL:** `{{ program_url }}`
- **Scope Revision (SHA-256):** `{{ scope_revision }}`
- **Forbidden Techniques:** `INTRUSIVE` (Exploitation, credential stuffing, denial-of-service, brute-forcing).

---

## Confirmed findings

<!-- If no confirmed findings were identified, this section states: "No confirmed findings" -->

{% if confirmed_findings %}
{% for finding in confirmed_findings %}
### {{ finding.id }}: {{ finding.title }}

- **Severity:** `{{ finding.severity | upper }}`
- **Confidence:** `confirmed` (Verified via deterministic scanner evidence)
- **Affected Asset:** `{{ finding.affected_asset }}`
- **Source Tool:** `{{ finding.source_tool }}` (Action: `{{ finding.source_action_id }}`)
- **Audit Citation:** `{{ finding.audit_citation }}`

#### Severity Rationale
{{ finding.severity_rationale }}

#### Evidence
```text
{{ finding.evidence }}
```

#### Reproducibility
```bash
{{ finding.reproducibility }}
```

#### Remediation Guidance
{{ finding.remediation }}

#### References
{% for ref in finding.references %}
- [{{ ref }}]({{ ref }})
{% endfor %}

---
{% endfor %}
{% else %}
No confirmed findings were identified during this assessment.
{% endif %}

---

## Hypotheses

<!-- Speculative observations, ambiguous scanner responses, or LLM-proposed leads -->

{% if hypothesis_findings %}
{% for finding in hypothesis_findings %}
### {{ finding.id }}: {{ finding.title }}

- **Severity:** `{{ finding.severity | upper }}`
- **Confidence:** `hypothesis` (Unconfirmed observation / ambiguous response)
- **Affected Asset:** `{{ finding.affected_asset }}`
- **Source Tool:** `{{ finding.source_tool }}` (Action: `{{ finding.source_action_id }}`)
- **Audit Citation:** `{{ finding.audit_citation }}`

#### Technical Observation
{{ finding.severity_rationale }}

#### Raw Scanner Output
```text
{{ finding.evidence }}
```

#### Suggested Verification Steps
```bash
{{ finding.reproducibility }}
```

#### Remediation & Hardening Note
{{ finding.remediation }}

#### References
{% for ref in finding.references %}
- [{{ ref }}]({{ ref }})
{% endfor %}

---
{% endfor %}
{% else %}
No exploratory hypotheses recorded.
{% endif %}

---

## Methodology & Execution Trail

Assessments follow Viper's four-phase safety and execution lifecycle:
1. **Plan Proposal:** Autonomous or guided test plan formulation with parameter boundary checks.
2. **Policy Evaluation & Gate:** Deterministic scope validation against `scope.yaml`. All active scanning required explicit human operator approval.
3. **Isolated Execution:** Headless execution via `RemoteExecutor` over an encrypted IAP tunnel to an isolated cloud Kali execution environment.
4. **Deterministic Analysis:** Tool output parsed directly by regex/JSON parsers without LLM modification, guaranteeing zero fabricated vulnerabilities.

---

## Cryptographic Audit Trail & Integrity Attestation

Every operational action, policy evaluation, human approval, and scanner dispatch was recorded in an append-only, SHA-256 hash-chained audit log.

- **Audit Log File:** `data/audit/{{ project_id }}.jsonl`
- **Total Logged Events:** `{{ audit_event_count }}`
- **Genesis Hash (`seq=0`):** `0000000000000000000000000000000000000000000000000000000000000000`
- **Chain Head Hash:** `{{ chain_head_hash }}`
- **External Anchor Provider:** `{{ anchor_provider }}` (Status: `{{ anchor_status }}`)
- **Anchor Receipt Token:** `{{ anchor_token }}`

### Audit Event Citations

| Citation | Sequence | Event Type | Action ID | Event SHA-256 Hash |
|:---|:---:|:---|:---|:---|
{% for event in audit_citations %}
| `[{{ event.citation }}]` | `{{ event.seq }}` | `{{ event.event }}` | `{{ event.action_id }}` | `{{ event.hash }}` |
{% endfor %}

### Integrity Verification Command
To independently verify the authenticity and sequence of this assessment's audit log:
```bash
viper audit verify --project {{ project_id }}
```
