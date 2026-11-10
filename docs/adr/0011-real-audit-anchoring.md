# ADR 0011: Real RFC-3161 audit-head timestamp anchoring via OpenSSL and trusted CA bundles

Status: Accepted (2026-11-09)

## Context

Phase 4 of Viper's safety architecture requires tamper-evident, verifiable audit logging. All agent actions, policy decisions, and scanner results are recorded in an append-only hash-chained JSONL audit trail (`data/audit/{project_id}.jsonl`) with a deterministic genesis block (`seq=0`, `prev_hash=0*64`) and per-event SHA-256 hashing.

While this hash chain provides robust tamper detection against unauthorized modification, insertion, or truncation, it possesses a fundamental limitation: **it cannot independently prove when the records were created**. A party with access to the local machine could retroactively rewrite or forge an entire audit log with arbitrary timestamps while maintaining valid internal hash chain consistency.

In Milestone M7 and ADR 0010, Viper introduced the anchoring interface (`AnchorReceipt`, `submit_tsa`, `submit_rekor`, `verify_anchor`, and `anchor_verdict`), but external verification was stubbed with a mock provider (`provider="mock"`). Mock receipts prove self-consistency (`CONSISTENT_ONLY`), but provide zero third-party cryptographic notarization.

In v1.1, Viper transitions audit anchoring from a design prototype to an operational, cryptographically binding mechanism using RFC-3161 Timestamp Authorities (TSAs).

---

## Decision

1. **Standardized RFC-3161 Protocol:**
   - Viper uses the IETF RFC 3161 / RFC 5816 standard for cryptographic timestamping.
   - When external anchoring is enabled (`VIPER_ANCHOR_TSA_URL` configured with explicit opt-in `allow_network=True`), Viper constructs an ASN.1 `TimeStampReq` requesting a SHA-256 message imprint of the exact 64-hex audit head hash with `certReq=True` (instructing the authority to include its certificate chain in the response).
   - The server response (`application/timestamp-reply`) containing the DER-encoded `TimeStampResp` is retained in full, base64-encoded, within `AnchorReceipt(provider="tsa", head_hash=..., token=...)`.

2. **Subprocess Verification via OpenSSL CLI (`openssl ts`):**
   - **Rationale:** Parsing complex ASN.1 structures, CMS/PKCS#7 signed data, and X.509 certificate chains in pure Python introduces substantial attack surface, performance overhead, and dependency bloat (`pyasn1`, `cryptography`, `asn1crypto`). Viper delegates cryptographic verification to the operating system's battle-tested `openssl` CLI binary.
   - Verification executes in two discrete, deterministic steps:
     1. **Time Extraction:**
        ```bash
        openssl ts -reply -in <token_file> -text
        ```
        Extracts the token's authenticated UTC timestamp line (e.g. `Time stamp: Nov  9 04:24:53 2026 GMT`) and converts it to a standard Unix epoch integer.
     2. **Cryptographic Validation:**
        ```bash
        openssl ts -verify -in <token_file> -digest <head_hash> -sha256 -CAfile <ca_bundle> -attime <epoch>
        ```
        Validates the ASN.1 status, confirms the signed digest imprint exactly matches `head_hash`, verifies the cryptographic signature over the timestamp token, and validates the TSA certificate chain against the trusted CA bundle. OpenSSL must return exit code 0 and emit `Verification: OK`.

3. **Mandatory Historical Verification via `-attime <epoch>`:**
   - **The Problem:** In public key infrastructure (PKI), timestamp authority signing certificates are deliberately short-lived (typically 1 to 3 years) for cryptographic hygiene. Standard X.509 certificate path validation verifies validity against the current system clock. If an assessment conducted in 2026 is audited or reviewed in 2028 after the TSA signing certificate expires, standard verification fails.
   - **The Solution:** Passing `-attime <epoch>` instructs OpenSSL to evaluate certificate path validity as of the token's own authenticated generation timestamp (`genTime`). This ensures historical verification remains reliable indefinitely.

4. **Process Isolation & Defense-in-Depth:**
   - The token is written to a private temporary file within a restricted `tempfile.TemporaryDirectory()`, ensuring all artifacts are wiped immediately after verification.
   - Subprocess invocations use strict argument lists (`argv`), avoiding shell invocation (`shell=False`, `stdin=subprocess.DEVNULL`).
   - Minimal sanitized environment: the subprocess does not inherit sensitive environmental variables.
   - Strict execution limits: 20-second timeout (`timeout=20.0`), token size ceiling of 256 KiB (`MAX_TOKEN_BYTES = 256 * 1024`), and strict digest formatting regex (`^[a-f0-9]{64}$`).
   - Fail-closed error handling: any unexpected error (missing OpenSSL binary, timeout, corrupted DER, invalid digest, wrong root) cleanly returns `False` without throwing uncaught exceptions.

5. **Trust Anchor Architecture:**
   - By default, Viper uses the Mozilla CA bundle provided by `certifi.where()` (`Settings.anchor_tsa_certifi_ca = True`).
   - Operators can supply custom or private enterprise Root CA certificates via `Settings.anchor_tsa_ca_file`.

6. **What is NOT Covered (Operational Boundaries):**
   - **Revocation Checking (CRL / OCSP):** Deliberately excluded. Offline verification must never trigger outbound network requests.
   - **TSA Trust Policy:** Viper trusts any TSA whose root certificate resides in the configured trust bundle (Certifi or custom CA file); domain-specific TSA policy restrictions are left to PKI management.
   - **Mock vs. Real:** Mock receipts verify internal consistency only and yield `CONSISTENT_ONLY` in `anchor_verdict`. Only genuine RFC-3161 tokens verified against a trusted root return `True`, yielding the authoritative `VERIFIED` verdict.

---

## Consequences

### Positive
- Indisputable, third-party cryptographic proof that pentest findings and audit logs existed at a specific time.
- Zero pure-Python cryptographic dependency overhead; uses standard OS `openssl`.
- Resilient long-term auditability via `-attime` historical timestamp evaluation.
- Fully offline verification with zero external network leakage.

### Negative / Trade-offs
- Verification requires the `openssl` CLI binary to be installed on the operator's system.
- Revocation of compromised TSA keys must be handled via CA bundle updates rather than real-time OCSP checks.
