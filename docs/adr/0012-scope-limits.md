# ADR 0012: Enforced scope rate limits, automation policy, and technique constraints

Status: Accepted (2026-11-09)

## Context

In Viper v1.0, scope enforcement focused on asset boundaries: target hostnames, wildcard domains (`*.example.com`), and CIDR ranges, with exclusions strictly overriding inclusions (`in_scope`, `exclusions`).

However, professional penetration testing rules of engagement and bug bounty policies regularly impose operational constraints beyond asset definitions:
1. **Rate Limits:** Programs frequently stipulate maximum scanning rates (e.g. "Do not exceed 5 requests/sec" or "Rate limit to 1 req/sec").
2. **Automation Bans:** Certain programs permit manual inspection while strictly forbidding automated vulnerability scanners or automated tools.
3. **Technique Exclusions & Inclusions:** Policies may permit basic port discovery while forbidding active web vulnerability scanning, brute-forcing, or denial-of-service simulations.

In v1.0, scanner request rates were hardcoded in CLI flags (e.g. Nuclei `-rl 5`), and `forbidden_techniques` consisted of free-text strings for human reference without automated enforcement by `viper.policy.engine`.

In v1.1, Viper introduces deterministic, fail-closed enforcement of operational limits within the core policy engine.

---

## Decision

1. **Scope Data Model Extensions (`viper.policy.models.Scope`):**
   The `Scope` model gains three additive, strictly validated fields:
   - `max_rate_rps: int | None = Field(default=None, ge=1, le=1000, strict=True)`: Maximum permitted request rate in requests per second. `None` indicates no explicit program-level cap (tool default applies).
   - `automation_allowed: bool = Field(default=True, strict=True)`: Boolean flag indicating whether automated scanning tools are permitted.
   - `permitted_techniques: tuple[str, ...] = ()`: An optional allowlist of canonical technique slugs (maximum 20 entries). If populated, any tool employing a technique outside this allowlist is denied.
   - **Backward Compatibility:** All new fields possess defaults that reproduce v1.0 behavior (`max_rate_rps=None`, `automation_allowed=True`, `permitted_techniques=()`), allowing existing scope YAML files to load seamlessly. Recomputing `scope.revision` incorporates these fields into the canonical SHA-256 hash.

2. **Registry-Owned Technique Tags & Rate Defaults:**
   - In accordance with Viper's principle that models must never declare their own permissions or risk ratings, technique tags are strictly registry-owned.
   - `ToolInfo` models include:
     - `techniques: frozenset[str]`: Canonical technique slugs (e.g. `nmap` = `{"port-scan", "service-detection"}`, `nuclei` = `{"web-scan", "template-scan"}`, read-only stubs = `frozenset()`).
     - `default_rate_rps: int | None`: Default rate applied when an action omits the `rate_limit` argument (e.g. 5 rps for Nuclei).
   - Known technique slugs are strictly enumerated in `KNOWN_TECHNIQUES`:
     `port-scan`, `service-detection`, `web-scan`, `template-scan`, `passive-scan`, `spider`, `brute-force`, `dos`, `exploit`.

3. **Deterministic Policy Evaluation (`viper.policy.engine._scope_limit_reason`):**
   The policy engine evaluates operational constraints fail-closed before granting `ALLOW` or `REQUIRE_APPROVAL`:
   - **Automation Check:** If `tool.risk == RiskLevel.ACTIVE and not scope.automation_allowed`:
     DENY with `"automated tools are not permitted by this scope"`.
   - **Rate Limit Check:** If `scope.max_rate_rps is not None`:
     - The rate cap explicitly bounds HTTP scanner traffic (`nuclei`) via its `-rl` argument. `nmap` has no rate argument and runs under port and target host scope.
     - Missing action `rate_limit` defaults to `tool.default_rate_rps`.
     - Invalid rates (null, boolean, string, or < 1) fail closed with `"rate <value!r> is not a valid rate_limit"`.
     - If rate exceeds `scope.max_rate_rps`:
       DENY with `"rate {rate} exceeds scope limit {scope.max_rate_rps} rps"`.
   - **Forbidden Techniques:** Evaluated by intersecting normalized slugs from `scope.forbidden_techniques` with `KNOWN_TECHNIQUES`. If any tool technique is present in the forbidden set:
     DENY with `"technique '{technique}' is forbidden by scope"`. Free-text entries that do not normalize to a known slug (e.g. legacy `"INTRUSIVE"`) are ignored by the automated engine and kept for human operators.
   - **Permitted Techniques:** If `scope.permitted_techniques` is non-empty, every technique tag of the tool must be in the permitted list. If any technique is unlisted:
     DENY with `"technique '{technique}' is not in the scope's permitted techniques"`.

4. **Scope Drafting Assistant (`viper.policy.scope_draft`):**
   - Maps natural-language program rules to technique slugs using a deterministic alias table (e.g. "port scanning" -> "port-scan", "denial of service" -> "dos").
   - Adds mandatory ambiguity warnings for any unmapped technique mentioned in program text.
   - Performs deterministic pattern scanning on untrusted program text for automation bans (e.g. "Automated scanning is prohibited", "No automated tools or scanners are allowed"). If detected, it sets `automation_allowed = False` and reserves a high-priority ambiguity warning that cannot be suppressed or bypassed by model output.

5. **End-to-End Invariant:**
   - Setting `automation_allowed: false` in a scope guarantees that `viper agent run` will evaluate policy on all active tools (such as Nmap and Nuclei), issue immediate policy denials, and execute zero network commands.

---

## Consequences

### Positive
- Strict alignment with bug bounty program constraints (rate limits and technique restrictions).
- Fail-closed security: omission of rate limits cannot bypass scope limits, and unmapped permitted techniques cause denials.
- Complete immutability: models cannot override tool technique classifications.
- Full backward compatibility for existing scope files.

### Negative / Trade-offs
- Scope revisions (`scope.revision`) change for existing scope files because the new fields are serialized into the canonical JSON hash.
- Strict slug validation requires human approval to map novel or non-standard technique descriptions into recognized slugs.
