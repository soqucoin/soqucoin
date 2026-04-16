---
description: Detects sharp edges - error-prone APIs, dangerous configurations, and footgun designs that enable security mistakes
---

# Sharp Edges Audit

Identifies security-relevant API designs that enable mistakes through developer confusion, laziness, or malice. Adapted from Trail of Bits audit methodology.

## When to Invoke

Use `/sharp-edges` when:
- Reviewing API designs for security-relevant interfaces
- Auditing configuration schemas that expose security choices
- Evaluating cryptographic library ergonomics
- Assessing authentication/authorization APIs
- Any code review where developers make security-critical decisions

## Methodology

Analyze code through the lens of three adversaries:

### 1. The Scoundrel
Can a malicious developer or attacker disable security via configuration?
- Look for: `debug=true`, `verify=false`, `skip_auth` flags
- Check: Can security be disabled without leaving audit trail?

### 2. The Lazy Developer
Will copy-pasting the first example lead to insecure code?
- Check: Do examples in comments/docs show secure usage?
- Look for: Insecure code snippets that might be copied

### 3. The Confused Developer
Can parameters be swapped without type errors?
- Look for: `encrypt(msg, bytes, bytes)` where key/nonce can be swapped
- Check: Are security-critical parameters clearly typed?

## Sharp Edge Categories

Scan for these six categories of misuse-prone designs:

| Category | What to Look For |
|----------|------------------|
| **Algorithm Selection** | User-controllable algorithm choice (JWT `alg: none`, weak hash selection) |
| **Dangerous Defaults** | `timeout: 0` meaning infinite; empty password accepted; `*` wildcards |
| **Primitive vs Semantic APIs** | Generic byte array params that can be swapped (key vs nonce) |
| **Configuration Cliffs** | Single flag that disables entire security subsystem |
| **Silent Failures** | Verification returns False instead of throwing; ignored return values |
| **Stringly-Typed Security** | Permissions as comma-separated strings; SQL from concatenation |

## Execution Steps

1. **Identify entry points**: Find public APIs, configuration parsers, RPC handlers
2. **Map security decisions**: List all places where security choices are made
3. **Apply adversary lenses**: For each decision point, consider all three adversaries
4. **Check defaults**: Verify secure-by-default behavior
5. **Test parameter confusion**: Check if security-critical params can be swapped
6. **Document findings**: Create findings with severity, location, and remediation

## Output Format

For each sharp edge found, document:

```
## Finding: [Title]
**Severity:** Critical/High/Medium/Low
**Category:** [One of the six categories]
**Location:** file:line
**Adversary:** Scoundrel/Lazy/Confused

### Description
[What the sharp edge is]

### Impact
[What could go wrong]

### Remediation
[How to fix it]
```

## Soqucoin-Specific Focus Areas

Given the post-quantum cryptocurrency context:
- Dilithium key generation and signing APIs
- AuxPoW consensus configuration
- RPC authentication and authorization
- Wallet encryption and key derivation
- Network peer validation settings
- Bulletproofs++ range proof configuration
