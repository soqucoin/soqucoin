---
description: Detect timing side-channel vulnerabilities in cryptographic code by analyzing execution paths
---

# Constant-Time Analysis

Analyzes cryptographic code for timing side-channel vulnerabilities. Detects instructions and patterns that could leak secret data through execution timing. Adapted from Trail of Bits methodology.

## When to Invoke

Use `/constant-time` when:
- Auditing cryptographic implementations (Dilithium, Bulletproofs++)
- Reviewing key comparison or signature verification code
- Analyzing password/secret handling functions
- Checking hash functions operating on secrets
- Any code where secret data influences control flow

## Background

Timing attacks exploit measurable differences in execution time based on secret values. Common sources:
1. **Variable-time instructions** (division, modulo on secrets)
2. **Secret-dependent branches** (if/else based on secret bits)
3. **Secret-dependent memory access** (cache timing)
4. **Early exit patterns** (return on first difference)

## Vulnerability Categories

### Error Level (Must Fix)

| Category | What to Look For |
|----------|------------------|
| **Integer Division** | Division/modulo operations on secret values |
| **FP Division** | Floating-point division on secrets |
| **Square Root** | Variable-time sqrt on secret values |
| **Variable-time Comparison** | `memcmp`, `strcmp` on secrets |
| **Early Exit** | Loop breaks on first difference |

### Warning Level (Review Needed)

| Category | What to Look For |
|----------|------------------|
| **Conditional Branches** | if/else based on secret bits |
| **Switch Statements** | switch on secret values |
| **Loop Bounds** | Loop count depends on secret |
| **Table Lookups** | Array index from secret (cache timing) |

## Analysis Steps

### Step 1: Identify Secret Variables
Map all variables that hold or derive from secrets:
- Private keys
- Passwords/PINs
- Nonces/random values
- Intermediate cryptographic state
- Plaintext/ciphertext in certain contexts

### Step 2: Trace Secret Data Flow
Track how secrets propagate through code:
```
secret -> derived_value -> comparison -> branch
```

### Step 3: Check Operations on Secrets

**Variable-Time Operations (VIOLATION):**
```cpp
// BAD: Division timing depends on secret
result = secret_value / divisor;

// BAD: Modulo timing varies
remainder = secret % modulus;

// BAD: strcmp stops on first difference
if (strcmp(user_password, stored_hash) == 0) // TIMING LEAK
```

**Constant-Time Alternatives:**
```cpp
// GOOD: Constant-time comparison
CRYPTO_memcmp(a, b, len);

// GOOD: Bitwise selection instead of branch
result = (mask & a) | (~mask & b);

// GOOD: Barrett reduction instead of division
barrett_reduce(secret, modulus);
```

### Step 4: Check Control Flow

**Violations:**
```cpp
// BAD: Branch on secret bit
if (secret_key[i] & bit_mask) {
    do_expensive_operation();
}

// BAD: Early return on difference
for (int i = 0; i < len; i++) {
    if (a[i] != b[i]) return false;  // TIMING LEAK
}
```

**Safe Patterns:**
```cpp
// GOOD: Process all bytes regardless
unsigned char result = 0;
for (int i = 0; i < len; i++) {
    result |= a[i] ^ b[i];
}
return result == 0;
```

## Soqucoin Focus Areas

### Critical (Must Be Constant-Time)
1. **Dilithium signature verification** - `src/crypto/dilithium/`
   - Key comparison operations
   - Polynomial arithmetic
   - NTT operations

2. **Bulletproofs++ proofs** - `src/crypto/bulletproofs/`
   - Range proof verification
   - Inner product arguments
   - Scalar multiplications

3. **Key derivation** - `src/wallet/`
   - PBKDF2/scrypt operations
   - BIP32 child key derivation

4. **Address comparison** - `src/script/`
   - Script evaluation with secrets

### To Verify
```bash
# Search for potential timing issues
grep -rn "memcmp\|strcmp" src/crypto/ --include="*.cpp"
grep -rn "if.*secret\|if.*key\|if.*private" src/ --include="*.cpp"
grep -rn "% \|/ \|%=\|/=" src/crypto/ --include="*.cpp"
```

## Output Format

```
## Finding: [Timing Vulnerability Title]
**Severity:** Critical / High / Medium
**Type:** Division | Branch | Comparison | Memory Access
**Location:** file:line

### Vulnerable Code
```cpp
[code snippet]
```

### Secret Data Path
secret_variable -> [transformations] -> vulnerable_operation

### Attack Scenario
[How timing could be exploited]

### Remediation
```cpp
[constant-time replacement]
```
```

## References

- [A Hacker's Guide to Crafting Constant-Time Code](https://www.bearssl.org/constanttime.html)
- [Timing Attacks on Implementations](https://timing.attacks.cr.yp.to/)
- NIST SP 800-185: SHA-3 Derived Functions (constant-time requirements)
