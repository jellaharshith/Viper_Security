# ADR 0013: Scope boundaries and asset exclusions for Crypto.com HackerOne engagement

Status: Accepted (2026-11-11)

## Context

In extending Viper's capabilities to real-world bug bounty programs, the project has initiated an engagement against Crypto.com's HackerOne program ([`hackerone.com/crypto`](https://hackerone.com/crypto)).

Crypto.com is a major regulated cryptocurrency exchange securing real user funds with a top bounty of $1,000,000. The program scope encompasses 24 assets organized into five distinct tiers:
1. **Low Bounty Tier ($10–$500):** Static asset CDNs, developer portals, developer APIs, travel, ticketing, tax, and experiences microservices (`js.crypto.com`, `developer.crypto.com`, `developer-api.crypto.com`, `developer-platform-api.crypto.com`, `travel.crypto.com`, `tickets.crypto.com`, `tax.crypto.com`, `experiences.crypto.com`, `crypto.com/nft`, `crypto.com/price`).
2. **Extreme Tier Eligible ($100–$1,000,000):** Core exchange assets, including `crypto.com/exchange`, "mobile app APIs that require an account", "Exchange APIs that require an account", and `app.mona.co`.
3. **Extreme Tier Not Eligible ($10–$5,000):** Public surfaces and non-exchange platforms (`web.crypto.com`, `og.com`, `*.mona.co`, `*.crypto.com`, `com.monaco.mobile`, `co.mona.android`, `nadex.com`, `merchant.crypto.com`).
4. **Smart Contract ($1–$1,000,000):** Two mainnet smart contracts deployed on Cronos and Ethereum (CDCETH).
5. **Excluded Assets:** Program-designated out-of-scope targets (Crypto.com Wallet Extension, `com.defi.wallet` mobile apps, and specific GitHub source repositories: `swap-contracts-*`, `cro-staking`, `chain-desktop-wallet`).

Unlike traditional enterprise web scopes, the stakes of cryptocurrency exchange environments require rigorous operational fencing. An automated security scanner operating without precise boundaries could trigger financial transactions, lock real user accounts, violate financial regulations (KYC/AML), or cause denial of service on mission-critical matching engines.

This ADR records the architectural and policy decisions defining the approved boundaries for Round 1, specifically citing the program's published rules of engagement.

---

## Decision

Viper will strictly limit Round 1 testing to the twelve non-account-requiring web and API hostnames defined in `projects/crypto-h1/crypto-h1.draft.yaml`. All other asset classes are explicitly excluded based on the following programmatic and technical justifications:

### 1. Exclusion of Account-Requiring Assets (Exchange & Mobile APIs)
- **Program Rule Citation:** The program enforces strict identity verification: main consumer and exchange apps require Know-Your-Customer (KYC) identity verification with legal identity documentation. Crucially, the program rules stipulate:
  > *"No draining another user's funds or blocking their access — automatic disqualification."*
  
  The rules additionally prohibit targeting users, employees, or staff, touching non-owned accounts, and unauthorized data collection.
- **Decision & Rationale:** Viper agents must never attempt automated account creation on regulated exchanges, as generating fake identities violates financial compliance regulations and program terms. Furthermore, testing authenticated exchange endpoints with autonomous planning agents introduces the risk of inadvertently invoking trade, withdrawal, or fund transfer mutations. Deep authenticated flows (`crypto.com/exchange` authenticated routes, account-requiring mobile APIs, and account-requiring exchange APIs) are excluded from Round 1. If testing of these assets is conducted in the future, the operator must provide an isolated, pre-authenticated, rate-limited test session via VM-local configuration files (`VIPER_EXEC_*_SESSION_FILE`), preserving complete credential isolation from the orchestrator.

### 2. Exclusion of Smart-Contract Assets
- **Program Rule Citation:** The Crypto.com program specifies strict criteria for smart-contract vulnerability reports:
  > *"Smart-contract reports need a real PoC; theoretical attacks (governance, oracle, sybil, liquidity) are explicitly invalid."*
- **Decision & Rationale:** Viper is architected for network and web application security testing using Nmap, Nuclei, and HTTP/web probes. Smart-contract security assessment requires specialized tooling for EVM bytecode analysis, Solidity AST analysis, symbolic execution, and local testnet fork fuzzing (such as Slither, Mythril, Foundry/Anvil, Echidna, or Certora). Viper does not possess an EVM execution engine or smart-contract analysis capabilities. Attempting to scan smart-contract addresses using web security tooling is technically ineffective and fails the program's mandatory executable Proof of Concept requirement.

### 3. Exclusion of Mobile Application Binaries (`com.monaco.mobile`, `co.mona.android`)
- **Program Rule Citation:** The assets `com.monaco.mobile` (iOS) and `co.mona.android` (Android) represent compiled mobile client application packages.
- **Decision & Rationale:** Security testing of compiled mobile packages requires dedicated mobile application testing infrastructure: APK/IPA decompilation (Apktool, Jadx), static binary analysis, dynamic instrumentation (Frida, objection), and mobile SSL pinning bypass mechanisms. Viper's execution plane is a headless Linux virtual machine running network and HTTP CLI tools. Mobile binary instrumentation is outside Viper's architectural scope and is excluded this round.

### 4. Exclusion of Program-Designated Excluded Assets
- **Program Rule Citation:** The HackerOne program policy explicitly designates the Crypto.com Wallet Extension, `com.defi.wallet` (DeFi Wallet mobile apps), and specific GitHub source repositories (`swap-contracts-*`, `cro-staking`, `chain-desktop-wallet`) as **"Excluded Assets"**.
- **Decision & Rationale:** Under HackerOne rules of engagement, conducting security research against assets explicitly marked as excluded is a direct violation of the program policy, leading to immediate report rejection, negative reputation impact, and potential platform disqualification. These assets are excluded unconditionally from `in_scope` and will never be contacted.

### 5. Treatment of URL-Type Assets
- **Program Scope Fact:** The program lists `crypto.com/price`, `crypto.com/nft`, and the public web surface of `crypto.com/exchange` as in-scope assets.
- **Decision & Rationale:** Viper's policy model (`viper.policy.models.Scope`) strictly validates `in_scope` entries as bare hostnames, wildcard domain patterns (`*.domain`), or CIDR blocks (per ADR 0008 and ADR 0012). Paths or URL schemes are rejected by the policy engine to prevent hostname spoofing and ensure clean firewall allowlist generation. Rather than creating an untested, ad-hoc schema extension, these assets are tracked in `ambiguities` as noted-but-not-yet-encoded. Their public web surfaces are covered via `web.crypto.com` or deferred until path-level routing is formally designed into the policy engine.

### 6. Retention of `graphql-introspection` on `merchant.crypto.com`
- **Program Rule Citation:** The program policy specifically notes:
  > *"merchant.crypto.com GraphQL DoS capped at $200"*
  
  This note explicitly confirms that GraphQL is an active, acknowledged attack surface on this merchant endpoint.
- **Decision & Rationale:** While DoS and resource-exhaustion attacks are globally forbidden (`dos` in `forbidden_techniques`), non-destructive single-query schema introspection (`{__schema{types{name}}}`) is read-only and benign. It enables structural API mapping without flooding the service. Therefore, `graphql-introspection` is retained in `permitted_techniques` globally and for `merchant.crypto.com`, while `dos` remains enforced as a fail-closed global restriction.

---

## Consequences

### Positive
- **Guaranteed Policy Compliance:** 100% compliance with Crypto.com's HackerOne program rules, eliminating the risk of disqualification.
- **Financial Safety:** Complete protection against unauthorized fund movements, account lockouts, or trading mutations.
- **Regulatory Alignment:** Avoids synthetic account creation on a regulated exchange.
- **Fail-Closed Enforcement:** The policy engine will automatically deny any action targeting excluded assets or account-requiring APIs before network dispatch.

### Negative / Trade-offs
- **Bounty Ceiling:** Extreme Tier bounties (up to $1,000,000) that require authenticated exchange API access and Smart Contract bounties ($1–$1,000,000) cannot be captured in this round.
- **Scope Restriction:** Testing is restricted to the Low Bounty Tier ($10–$500) and unauthenticated Extreme Tier Not Eligible assets ($10–$5,000).
