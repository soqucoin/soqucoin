# Soqucoin Wallet Cryptographic Specification

> **Version**: 1.0 | **Date**: January 23, 2026
> **Classification**: Technical Reference
> **Standard Compliance**: NIST FIPS 204, NIST SP 800-56C, NIST SP 800-132
> **Review Status**: Draft - Pending Cryptographer Review

---

## 1. Overview

This specification defines the cryptographic primitives, parameters, and protocols used in the Soqucoin wallet for key generation, signature creation, address derivation, and wallet file encryption.

### Design Philosophy

1. **Post-Quantum by Default**: All signing uses NIST-standardized lattice cryptography
2. **Conservative Parameters**: NIST Level 2 (128-bit classical and quantum security)
3. **Deterministic Where Possible**: Reproducible outputs from same inputs
4. **Defense in Depth**: Multiple layers (encryption + MAC + key stretching)

---

## 2. Signature Scheme: Dilithium (ML-DSA-44)

### 2.1 Algorithm Selection

| Property | Value | Rationale |
|----------|-------|-----------|
| **Algorithm** | Dilithium (ML-DSA) | NIST FIPS 204 standardized |
| **Security Level** | Level 2 (NIST Category 2) | 128-bit classical/quantum security |
| **Variant** | ML-DSA-44 (Dilithium2) | Balance of size and security |

### 2.2 Parameters

```
┌────────────────────────────────────────────────────────────────┐
│                    ML-DSA-44 (Dilithium2) Parameters           │
├────────────────────────────────────────────────────────────────┤
│ Ring dimension (n)           │ 256                             │
│ Modulus (q)                  │ 8,380,417                       │
│ Number of polynomials (k, l) │ k=4, l=4                        │
│ Dropped bits (d)             │ 13                              │
│ Weight of challenge (τ)      │ 39                              │
│ Coefficient range (γ₁)       │ 2^17                            │
│ Coefficient range (γ₂)       │ (q-1)/88                        │
│ Hint bound (ω)               │ 80                              │
│ Repetition limit (β)         │ 78                              │
│ Security (classical)         │ ~128 bits                       │
│ Security (quantum)           │ ~128 bits (vs Grover/lattice)   │
└────────────────────────────────────────────────────────────────┘
```

### 2.3 Key Sizes

| Component | Size (bytes) | Notes |
|-----------|--------------|-------|
| Public Key | 1,312 | Stored in wallet, shared for verification |
| Secret Key | 2,560 | Never leaves secure storage |
| Signature | 2,420 | Attached to transactions |

### 2.4 Key Generation

```
ALGORITHM: KeyGen()

INPUTS:
  - seed: 32 bytes of entropy from CSPRNG

OUTPUTS:
  - pk: Public key (1,312 bytes)
  - sk: Secret key (2,560 bytes)

PROCESS:
  1. ξ ← H(seed)                          // Expand seed
  2. (ρ, ρ', K) ← G(ξ)                    // Generate matrix seed, secret key seed, K
  3. A ← ExpandA(ρ)                        // Generate matrix A ∈ R_q^{k×l}
  4. (s₁, s₂) ← ExpandS(ρ')               // Generate secret vectors
  5. t ← A·s₁ + s₂                         // Compute public vector
  6. (t₁, t₀) ← Power2Round(t, d)         // Round for compression
  7. pk ← (ρ, t₁)                          // Pack public key
  8. tr ← H(pk)                            // Compute public key hash
  9. sk ← (ρ, K, tr, s₁, s₂, t₀)          // Pack secret key

SECURITY NOTES:
  - seed MUST have 256 bits of entropy (CSPRNG)
  - sk MUST be stored in SecureBytes (memory-locked, wiped on free)
  - No intermediate values may be logged or persisted
```

### 2.5 Signature Generation

```
ALGORITHM: Sign(sk, M)

INPUTS:
  - sk: Secret key (2,560 bytes)
  - M: Message to sign (arbitrary length)

OUTPUTS:
  - σ: Signature (2,420 bytes)

PROCESS:
  1. Parse sk as (ρ, K, tr, s₁, s₂, t₀)
  2. A ← ExpandA(ρ)
  3. μ ← H(tr || M)                        // Message representative
  4. κ ← 0; (z, h) ← ⊥
  5. ρ' ← H(K || μ)                        // Deterministic nonce derivation
  6. WHILE (z, h) = ⊥:
       a. y ← ExpandMask(ρ', κ)           // Generate masking vector
       b. w ← A·y
       c. w₁ ← HighBits(w)
       d. c̃ ← H(μ || w₁)                  // Challenge hash
       e. c ← SampleInBall(c̃)             // Sample challenge polynomial
       f. z ← y + c·s₁                    // Compute response
       g. IF ||z||∞ ≥ γ₁ - β OR ||LowBits(A·z - c·t))||∞ ≥ γ₂ - β THEN
            κ ← κ + l; CONTINUE
       h. h ← MakeHint(-c·t₀, w - c·s₂ + c·t₀)
       i. IF ||c·t₀||∞ > γ₂ OR # of 1's in h > ω THEN
            κ ← κ + l; CONTINUE
  7. σ ← (c̃, z, h)

SECURITY NOTES:
  - Nonce ρ' is DETERMINISTIC from K and message (prevents nonce reuse)
  - Rejection sampling ensures signature does not leak secret key
  - Implementation MUST be constant-time (no data-dependent branches)
```

### 2.6 Signature Verification

```
ALGORITHM: Verify(pk, M, σ)

INPUTS:
  - pk: Public key (1,312 bytes)
  - M: Message (arbitrary length)
  - σ: Signature (2,420 bytes)

OUTPUTS:
  - Boolean: true if valid, false otherwise

PROCESS:
  1. Parse pk as (ρ, t₁)
  2. Parse σ as (c̃, z, h)
  3. IF ||z||∞ ≥ γ₁ - β THEN RETURN false
  4. A ← ExpandA(ρ)
  5. tr ← H(pk)
  6. μ ← H(tr || M)
  7. c ← SampleInBall(c̃)
  8. w'₁ ← UseHint(h, A·z - c·t₁·2^d)
  9. RETURN c̃ = H(μ || w'₁)
```

---

## 3. Key Derivation

### 3.1 Hierarchical Deterministic (HD) Key Derivation

Soqucoin uses a modified BIP-44 derivation path adapted for post-quantum keys:

```
DERIVATION PATH:
  m / purpose' / coin_type' / account' / change / address_index

WHERE:
  purpose     = 44      (BIP-44 standard)
  coin_type   = 21329   (Soqucoin registered with SLIP-0044)
  account     = 0-n     (Account index, hardened)
  change      = 0 or 1  (0 = receiving, 1 = change)
  address_index = 0-n   (Address index within chain)

EXAMPLE:
  m/44'/21329'/0'/0/0  → First receiving address of first account
  m/44'/21329'/0'/1/0  → First change address of first account
```

### 3.2 HKDF-Based Key Derivation

```
ALGORITHM: DeriveKey(master_seed, path)

INPUTS:
  - master_seed: 64 bytes from BIP-39 seed
  - path: Derivation path string (e.g., "m/44'/21329'/0'/0/0")

OUTPUTS:
  - child_seed: 32 bytes suitable for Dilithium KeyGen

PROCESS:
  1. ikm ← master_seed
  2. FOR EACH level IN path:
       a. info ← "soqucoin.key." || level || ".v1"
       b. salt ← level_bytes (4 bytes, big-endian)
       c. prk ← HKDF-Extract(salt, ikm)
       d. ikm ← HKDF-Expand(prk, info, 64)
  3. child_seed ← ikm[0:32]
  4. RETURN child_seed

HKDF PARAMETERS:
  - Hash function: SHA-256
  - Extract output: 32 bytes
  - Expand output: 64 bytes (truncated to 32 for Dilithium seed)

DOMAIN SEPARATION:
  Purpose         │ Domain String
  ────────────────┼─────────────────────────────────
  Spending keys   │ "soqucoin.key.spending.v1"
  View keys       │ "soqucoin.key.view.v1"
  Blinding factors│ "soqucoin.key.blinding.v1"
  L2 channels     │ "soqucoin.key.lightning.v1"
```

### 3.3 Blinding Factor Derivation (GAP-010 Fix)

```
ALGORITHM: DeriveBlindingFactor(master_seed, address_index, output_index, nonce)

INPUTS:
  - master_seed: 64 bytes
  - address_index: uint32 (which address is spending)
  - output_index: uint32 (which output in transaction)
  - nonce: int64 (transaction timestamp or counter)

OUTPUTS:
  - blinding: 32 bytes

PROCESS:
  1. chain_seed ← HKDF-Expand(master_seed, "soqucoin.key.blinding.v1", 32)
  2. info ← address_index || output_index || nonce  (16 bytes total)
  3. blinding ← HKDF-Expand(chain_seed, info, 32)
  4. RETURN blinding

SECURITY NOTES:
  - Each (address_index, output_index, nonce) tuple MUST be unique
  - Blinding factor reuse reveals the hidden value (catastrophic)
  - Wallet MUST track used indices and prevent reuse
```

---

## 4. Address Encoding

### 4.1 Address Format: Bech32m

```
ADDRESS STRUCTURE:
  ┌───────────┬────────────┬───────────────────────────┬──────────┐
  │   HRP     │  Separator │        Data               │ Checksum │
  │ (sq1/tsq1)│     "1"    │  (version + pkh_hash)     │ (6 chars)│
  └───────────┴────────────┴───────────────────────────┴──────────┘

HRP (Human-Readable Part):
  Network    │ HRP    │ Example
  ───────────┼────────┼───────────────────────────────
  Mainnet    │ sq1    │ sq1q5rvwwdc...
  Testnet    │ tsq1   │ tsq1q5rvwwd...
  Stagenet   │ ssq1   │ ssq1q5rvww...

VERSION BYTE:
  0x00 = P2PQ      (Pay-to-Post-Quantum, single signature)
  0x01 = P2PQ_PAT  (P2PQ with PAT aggregation hint)
  0x02 = P2SH_PQ   (Pay-to-Script-Hash, post-quantum)
```

### 4.2 Public Key Hashing

```
ALGORITHM: HashPublicKey(pk)

INPUTS:
  - pk: Dilithium public key (1,312 bytes)

OUTPUTS:
  - pkh: Public key hash (20 bytes)

PROCESS:
  1. hash32 ← SHA-256(pk)           // First hash: compression
  2. pkh ← RIPEMD-160(hash32)       // Second hash: 20-byte output
  3. RETURN pkh

RATIONALE:
  - SHA-256 provides 128-bit collision resistance (quantum-safe)
  - RIPEMD-160 provides compact 20-byte addresses
  - Two-hash structure prevents length-extension attacks
```

### 4.3 Address Encoding

```
ALGORITHM: EncodeAddress(pk, network, type)

INPUTS:
  - pk: Dilithium public key (1,312 bytes)
  - network: MAINNET | TESTNET | STAGENET
  - type: P2PQ | P2PQ_PAT | P2SH_PQ

OUTPUTS:
  - address: Bech32m string

PROCESS:
  1. pkh ← HashPublicKey(pk)
  2. version ← GetVersionByte(type)
  3. data ← version || pkh
  4. hrp ← GetHRP(network)
  5. words ← ConvertToBase32(data)
  6. checksum ← Bech32mChecksum(hrp, words)
  7. address ← hrp || "1" || ToCharacters(words || checksum)
  8. RETURN address
```

### 4.4 Address Validation

```
ALGORITHM: ValidateAddress(address)

OUTPUTS:
  - Boolean, and if valid: (network, type, pkh)

PROCESS:
  1. (hrp, data) ← Bech32mDecode(address)
  2. IF decode failed THEN RETURN (false, ∅)
  3. IF hrp ∉ {"sq1", "tsq1", "ssq1"} THEN RETURN (false, ∅)
  4. IF length(data) ≠ 21 THEN RETURN (false, ∅)   // version + 20-byte hash
  5. network ← NetworkFromHRP(hrp)
  6. type ← TypeFromVersion(data[0])
  7. pkh ← data[1:21]
  8. RETURN (true, network, type, pkh)
```

---

## 5. Wallet File Encryption

### 5.1 Encryption Scheme

```
SCHEME: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)

┌─────────────────────────────────────────────────────────────────────┐
│                     ENCRYPTED WALLET FILE FORMAT                    │
├──────────┬──────────┬────────────┬──────────────────┬──────────────┤
│  Magic   │  Version │   Salt     │    Ciphertext    │     MAC      │
│ (4 bytes)│ (2 bytes)│ (16 bytes) │   (variable)     │  (32 bytes)  │
├──────────┼──────────┼────────────┼──────────────────┼──────────────┤
│ "SOQW"   │  0x0001  │   random   │ IV || E(plaintext)│ HMAC(ct)    │
└──────────┴──────────┴────────────┴──────────────────┴──────────────┘

Magic: 0x534F5157 ("SOQW" - Soqucoin Wallet)
Version: 0x0001 (allows future format evolution)
```

### 5.2 Key Derivation from Passphrase

```
ALGORITHM: DeriveEncryptionKey(passphrase, salt)

INPUTS:
  - passphrase: User-provided string (UTF-8)
  - salt: 16 random bytes (stored with encrypted file)

OUTPUTS:
  - key: 32 bytes (AES-256 key, also used for HMAC)

PROCESS (Cascading KDF with fallback):
  1. TRY Argon2id (preferred, memory-hard):
       key ← Argon2id(
         password  = passphrase,
         salt      = salt,
         t_cost    = 3,        // 3 iterations
         m_cost    = 65536,    // 64 MB memory
         p         = 4,        // 4 parallel threads
         dkLen     = 32
       )
  2. FALLBACK scrypt (if Argon2id unavailable):
       key ← scrypt(
         password  = passphrase,
         salt      = salt,
         N         = 32768,    // CPU/memory cost
         r         = 8,        // Block size
         p         = 1,        // Parallelization
         dkLen     = 32
       )
  3. LAST RESORT PBKDF2 (if scrypt unavailable):
       key ← PBKDF2-HMAC-SHA256(
         password   = passphrase,
         salt       = salt,
         iterations = 600,000, // OWASP 2023 for SHA-256
         dkLen      = 32
       )

IMPLEMENTATION NOTE:
  - Uses OpenSSL 3.x EVP_KDF API for all three algorithms
  - KDF selection is automatic based on OpenSSL provider availability
  - See pqcrypto.cpp WalletCrypto::DeriveKey() for implementation
```

### 5.3 Encryption Process

```
ALGORITHM: EncryptWallet(plaintext, passphrase)

INPUTS:
  - plaintext: Wallet data (serialized keys, metadata)
  - passphrase: User passphrase

OUTPUTS:
  - encrypted_file: Complete encrypted wallet file

PROCESS:
  1. salt ← GetRandomBytes(16)
  2. (enc_key, mac_key) ← DeriveEncryptionKey(passphrase, salt)
  3. iv ← GetRandomBytes(16)
  4. padded ← PKCS7Pad(plaintext, 16)
  5. ciphertext ← AES-256-CBC-Encrypt(enc_key, iv, padded)
  6. ct_with_iv ← iv || ciphertext
  7. mac ← HMAC-SHA256(mac_key, ct_with_iv)
  8. file_content ← magic || version || salt || ct_with_iv || mac
  9. Wipe(enc_key, mac_key, padded)   // Secure erase
  10. RETURN file_content

SECURITY NOTES:
  - IV MUST be random per encryption (NEVER reuse)
  - Encrypt-then-MAC prevents padding oracle attacks
  - All intermediate buffers MUST be wiped after use
```

### 5.4 Decryption Process

```
ALGORITHM: DecryptWallet(encrypted_file, passphrase)

INPUTS:
  - encrypted_file: Encrypted wallet file
  - passphrase: User passphrase

OUTPUTS:
  - plaintext: Decrypted wallet data, OR error

PROCESS:
  1. Parse encrypted_file:
       magic ← file[0:4]
       version ← file[4:6]
       salt ← file[6:22]
       ct_with_iv ← file[22:len-32]
       stored_mac ← file[len-32:len]
  2. IF magic ≠ "SOQW" THEN RETURN ERROR("Invalid wallet file")
  3. IF version ≠ 0x0001 THEN RETURN ERROR("Unsupported version")
  4. (enc_key, mac_key) ← DeriveEncryptionKey(passphrase, salt)
  5. computed_mac ← HMAC-SHA256(mac_key, ct_with_iv)
  6. IF NOT ConstantTimeCompare(stored_mac, computed_mac) THEN
       Wipe(enc_key, mac_key)
       RETURN ERROR("Invalid passphrase or corrupted file")
  7. iv ← ct_with_iv[0:16]
  8. ciphertext ← ct_with_iv[16:]
  9. padded ← AES-256-CBC-Decrypt(enc_key, iv, ciphertext)
  10. plaintext ← PKCS7Unpad(padded)
  11. Wipe(enc_key, mac_key, padded)
  12. RETURN plaintext

SECURITY NOTES:
  - MAC verification MUST be constant-time (prevent timing attacks)
  - MAC is verified BEFORE decryption (Encrypt-then-MAC property)
  - Passphrase errors and corruption return same error (no oracle)
```

---

## 6. Entropy Requirements

### 6.1 Entropy Sources

| Operation | Entropy Required | Source |
|-----------|------------------|--------|
| Key generation | 256 bits | OS CSPRNG |
| Wallet salt | 128 bits | OS CSPRNG |
| Encryption IV | 128 bits | OS CSPRNG |

### 6.2 CSPRNG Implementation

```
ALGORITHM: GetRandomBytes(n)

IMPLEMENTATION:
  - Linux: getrandom(2) syscall (blocking until entropy available)
  - macOS: SecRandomCopyBytes() or /dev/urandom
  - Windows: BCryptGenRandom()

FALLBACK BEHAVIOR:
  - If CSPRNG unavailable: ABORT (never use weak randomness)
  - No fallback to time-based or PID-based seeding

VERIFICATION:
  - At wallet startup, generate and verify 32 random bytes
  - Check for all-zeros or repeating patterns (sanity check)
```

---

## 7. Implementation Requirements

### 7.1 Constant-Time Operations

The following operations MUST be constant-time (no data-dependent branches or memory access patterns):

| Operation | Criticality | Verification Method |
|-----------|-------------|---------------------|
| Dilithium signing | 🔴 Critical | Reference implementation, timing tests |
| MAC comparison | 🔴 Critical | Explicit constant-time compare function |
| Secret key operations | 🔴 Critical | Code review, timing analysis |
| Passphrase comparison | 🟠 High | Never compare passphrases directly |

### 7.2 Memory Security

```
REQUIREMENTS FOR SecureBytes CLASS:

1. ALLOCATION:
   - Use mlock() to prevent swapping to disk
   - Allocate from secure heap if available

2. ZEROING:
   - Use explicit_bzero() or SecureZeroMemory()
   - Prevent compiler optimization of zeroing
   - Verify at assembly level that zeroing occurs

3. ACCESS:
   - Never log or print contents
   - Never pass to non-security-critical functions
   - Minimize lifetime (wipe immediately after use)

4. DESTRUCTION:
   - Wipe before free
   - Call munlock() after wipe
   - Set pointer to nullptr
```

### 7.3 Error Handling

```
SECURITY ERROR HANDLING PRINCIPLES:

1. FAIL CLOSED:
   - On any cryptographic error, fail the entire operation
   - Never proceed with partial or potentially compromised data

2. UNIFORM ERRORS:
   - "Invalid passphrase" and "corrupted file" return same error
   - Prevents error oracle attacks

3. NO RETRY AMPLIFICATION:
   - Rate limit passphrase attempts (wallet-level)
   - Consider exponential backoff after failures

4. SECURE CLEANUP:
   - On error, wipe all sensitive data before returning
   - Use try/finally or RAII patterns
```

---

## 8. Test Vectors

### 8.1 Dilithium Signature

```json
{
  "test_name": "dilithium_sign_verify",
  "secret_key_seed_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "message_hex": "536f717563696e20746573742076656374",
  "note": "Full signature vector in WALLET_TEST_VECTORS.md"
}
```

### 8.2 HKDF Key Derivation

```json
{
  "test_name": "hkdf_spending_key",
  "master_seed_hex": "000102...3f (64 bytes)",
  "path": "m/44'/21329'/0'/0/0",
  "expected_child_seed_hex": "... (32 bytes)",
  "note": "Verify deterministic derivation"
}
```

### 8.3 Address Encoding

```json
{
  "test_name": "mainnet_p2pq_encoding",
  "public_key_hash_hex": "0000000000000000000000000000000000000000",
  "network": "mainnet",
  "type": "P2PQ",
  "expected_address": "sq1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj9xr3f"
}
```

---

## 9. Security Considerations Summary

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| Key confidentiality | 128-bit PQ security | Dilithium ML-DSA-44 |
| Signature unforgeability | 128-bit PQ security | Dilithium security proof |
| Wallet at rest | 128-bit security | AES-256-CBC + HMAC |
| Passphrase brute-force | 100,000× slowdown | PBKDF2 iterations |
| Nonce uniqueness | Guaranteed | Deterministic derivation |
| Address integrity | Error detection | Bech32m checksum |

---

## 10. References

1. NIST FIPS 204 - Module-Lattice-Based Digital Signature Standard
2. NIST SP 800-56C Rev. 2 - Key Derivation Methods
3. NIST SP 800-132 - Password-Based Key Derivation
4. BIP-44 - Multi-Account Hierarchy for Deterministic Wallets
5. BIP-350 - Bech32m Format for v1+ Witness Addresses
6. RFC 5869 - HKDF: HMAC-based Extract-and-Expand Key Derivation Function
7. Ducas et al., "CRYSTALS-Dilithium" (original paper)

---

*Soqucoin Wallet Cryptographic Specification v1.0*
*January 2026*
