# Security Policy

## Supported Versions

| Version      | Supported          | Notes                        |
|------------- | ------------------ | -----------------------------|
| 1.0.x        | :white_check_mark: | Current release candidate    |
| < 1.0.0      | :x:                | Pre-release, do not deploy   |

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

### Contact

Email: [security@soqu.org](mailto:security@soqu.org)

To protect the confidentiality of your report, encrypt your email using the PGP key below.

### Response SLA

| Severity    | Acknowledgment | Patch Target   |
|------------ | -------------- | -------------- |
| Critical    | 24 hours       | 72 hours       |
| High        | 48 hours       | 7 days         |
| Medium      | 5 business days| 30 days        |
| Low         | 10 business days| Next release  |

### Disclosure Policy

We follow a **90-day responsible disclosure** window. After a fix is released, we will:
1. Credit the reporter (unless anonymity is requested)
2. Publish a security advisory via GitHub Security Advisories
3. Notify node operators via the `soqucoin-security` mailing list

### Bug Bounty

We offer bounties for qualifying vulnerabilities in the Soqucoin Core node:

| Severity     | Bounty Range       |
|------------- | -------------------|
| Critical     | Up to $50,000 USD  |
| High         | Up to $10,000 USD  |
| Medium       | Up to $2,000 USD   |
| Low          | Up to $500 USD     |

Bounty eligibility requires:
- First reporter of the vulnerability
- Responsible disclosure (no public disclosure before fix)
- Vulnerability must be in the latest supported release
- Not a known issue listed in our [Security Issue Registry](https://github.com/soqucoin/soqucoin/security/advisories)

### Scope

**In scope:**
- Consensus bugs (chain splits, inflation, double-spend)
- Post-quantum cryptography (Dilithium, PAT, LatticeFold)
- P2P network vulnerabilities (DoS, eclipse attacks)
- Wallet/key management (key leakage, weak derivation)
- RPC authentication bypass

**Out of scope:**
- Third-party dependencies (report upstream)
- Social engineering
- Physical attacks
- Bugs in unsupported versions

### PGP Key

For encrypted communication, please contact security@soqu.org to request the team's PGP public key.
