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
   - Ambiguous scanner states (`open|filtered`) or speculative model deductions are classified as `confidence="hypothesis"`.
4. **Audit Traceability:** All executed actions are recorded in `data/audit/lab-scanme.jsonl` with SHA-256 hash chains and notarized via `viper audit anchor`.
