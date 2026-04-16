---
description: Detects insecure default configurations that create vulnerabilities when running with missing or incomplete configuration
---

# Insecure Defaults Detection

Security skill for detecting insecure default configurations that create vulnerabilities when applications run with missing or incomplete configuration. Adapted from Trail of Bits audit methodology.

## Core Principle

**Fail-secure vs Fail-open**: Applications that crash without proper configuration are safe; applications that run with insecure defaults are vulnerable.

## When to Invoke

Use `/insecure-defaults` when:
- Security auditing production applications
- Configuration review of deployment manifests
- Pre-production checks before deploying
- Code review of authentication, authorization, or cryptographic code
- Environment variable handling analysis
- API security review (CORS, rate limiting, authentication)

## Categories to Detect

### 1. Hardcoded Fallback Secrets
```cpp
// BAD: Fallback to hardcoded key if env var missing
std::string key = getenv("SECRET_KEY") ? getenv("SECRET_KEY") : "default_key_12345";
```
- JWT signing keys
- API keys
- Session secrets
- Encryption keys

### 2. Default Credentials
- `admin/admin`, `root/password`, `test/test`
- Empty passwords that authenticate
- Debug accounts in production code

### 3. Weak Cryptographic Defaults
- MD5, SHA1 for security-critical hashing
- DES, 3DES, RC4 encryption
- ECB mode for block ciphers
- Small key sizes (RSA < 2048, EC < 256)
- NULL ciphers in TLS suites

### 4. Permissive Access Control
- `CORS: *` (allow all origins)
- `public: true` by default
- Missing authentication on endpoints
- Overly broad permissions

### 5. Fail-Open Behavior
```cpp
// BAD: Fails open on verification error
bool verify(sig) {
    try { return crypto_verify(sig); }
    catch(...) { return true; }  // FAIL-OPEN!
}
```

## Execution Steps

1. **Scan for environment variable fallbacks**
   ```bash
   grep -rn "getenv\|std::getenv\|os\.environ" --include="*.cpp" --include="*.h"
   ```

2. **Check configuration file defaults**
   - Look at `.conf.example`, `config.default`, sample configs
   - Identify security-relevant settings with insecure defaults

3. **Audit exception handlers**
   - Find all catch blocks in security-critical code
   - Verify they fail-secure (deny) not fail-open (allow)

4. **Review authentication code paths**
   - Check what happens with missing/empty credentials
   - Verify authentication is required, not optional

5. **Check network/CORS settings**
   - Look for wildcard allows
   - Verify restrictive defaults

## Output Format

```
## Finding: [Insecure Default Description]
**Severity:** Critical/High/Medium/Low
**Category:** [Secrets|Credentials|Crypto|Access|Fail-Open]
**Location:** file:line
**Behavior:** Fail-open / Weak default / Permissive allow

### Current Default
[What the current insecure default is]

### Secure Alternative
[What it should default to]

### Risk
[What could happen in production]

### Remediation
- Change default to [secure value]
- Require explicit configuration for [feature]
- Fail with error if [required config] missing
```

## Soqucoin-Specific Focus Areas

- **RPC server defaults**: Authentication required? Rate limiting?
- **P2P network settings**: Peer verification, connection limits
- **Wallet encryption**: Default key derivation parameters
- **Consensus parameters**: Difficulty adjustment, block validation
- **Testnet vs Mainnet**: Are testnet-only settings disabled on mainnet?
- **Debug flags**: Any `ENABLE_DEBUG`, `SKIP_VERIFY` that could leak to production?
- **Genesis configuration**: Hardcoded values that should be configurable?
