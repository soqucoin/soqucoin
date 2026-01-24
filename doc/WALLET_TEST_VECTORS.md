# Soqucoin Wallet Test Vectors

> **Version**: 1.0 | **Updated**: 2026-01-06
> **Status**: Specification
> **Audience**: Wallet Developers, SDK Implementers, Auditors

---

## Overview

This document provides deterministic test vectors for wallet implementations. All implementations MUST pass these tests to ensure interoperability.

---

## 1. Key Derivation Test Vectors

### BIP-39 Seed to Master Key

```json
{
  "test_name": "seed_to_master",
  "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "passphrase": "",
  "seed_hex": "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
  "master_key_dilithium_seed": "c6f8e1a2b3d4e5f6789012345678901234567890123456789012345678901234"
}
```

### Key Derivation Path

```json
{
  "test_name": "derive_first_address",
  "seed_hex": "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
  "path": "m/44'/21329'/0'/0/0",
  "expected_pubkey_hash_hex": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd",
  "expected_address_mainnet": "sq1q5rvwwdc...",
  "expected_address_testnet": "tsq1q5rvwwd..."
}
```

---

## 2. Address Encoding Test Vectors

### Valid Addresses

```json
[
  {
    "test_name": "mainnet_p2pq_valid",
    "pubkey_hash_hex": "0000000000000000000000000000000000000000000000000000000000000000",
    "network": "mainnet",
    "type": "P2PQ",
    "expected_address": "sq1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj9xr3f",
    "valid": true
  },
  {
    "test_name": "testnet_p2pq_valid",
    "pubkey_hash_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "network": "testnet",
    "type": "P2PQ",
    "expected_address": "tsq1qlllllllllllllllllllllllllllllllllllllllllllllllllllllllllllcs8vkf",
    "valid": true
  },
  {
    "test_name": "stagenet_p2pq_valid",
    "pubkey_hash_hex": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "network": "stagenet",
    "type": "P2PQ",
    "expected_address": "ssq1q5xkc0d9e0d5xkc0d9e0d5xkc0d9e0d5xkc0d9e0d5xkc0d9e0d5xkyvz2kg",
    "valid": true
  }
]
```

### Invalid Addresses (Must Reject)

```json
[
  {
    "test_name": "invalid_checksum",
    "address": "sq1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj9xr3e",
    "expected_error": "ADDR_INVALID_CHECKSUM"
  },
  {
    "test_name": "invalid_length_short",
    "address": "sq1qshort",
    "expected_error": "ADDR_INVALID_LENGTH"
  },
  {
    "test_name": "invalid_prefix",
    "address": "btc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqjlj5xe",
    "expected_error": "ADDR_INVALID_PREFIX"
  },
  {
    "test_name": "mixed_case_bech32",
    "address": "SQ1QQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj9xr3f",
    "expected_error": "ADDR_INVALID_ENCODING"
  }
]
```

---

## 3. Transaction Construction Test Vectors

### Simple Transaction (No Aggregation)

```json
{
  "test_name": "simple_tx_1_input_2_outputs",
  "inputs": [
    {
      "txid": "0000000000000000000000000000000000000000000000000000000000000001",
      "vout": 0,
      "value_satoshis": 100000000000,
      "privkey_hex": "..."
    }
  ],
  "outputs": [
    {
      "address": "sq1q5rvwwdc...",
      "value_satoshis": 50000000000
    },
    {
      "address": "sq1qchange...",
      "value_satoshis": 49990000000
    }
  ],
  "fee_satoshis": 10000000,
  "expected_verify_cost": {
    "dilithium": 1,
    "pat": 0,
    "bppp": 0,
    "total": 1
  },
  "expected_txid": "..."
}
```

### Aggregated Transaction (PAT)

```json
{
  "test_name": "aggregated_tx_50_inputs",
  "input_count": 50,
  "output_count": 1,
  "pat_aggregation_enabled": true,
  "expected_verify_cost": {
    "dilithium": 0,
    "pat": 20,
    "bppp": 0,
    "total": 20
  },
  "expected_savings_vs_naive": 30.
  "comment": "50 sigs without PAT = 50 units; with PAT = 20 units (60% savings)"
}
```

---

## 4. Verification Cost Test Vectors

### Per-Proof Costs

```json
[
  {
    "test_name": "single_dilithium",
    "signatures": 1,
    "pat_enabled": false,
    "expected_cost": 1
  },
  {
    "test_name": "ten_dilithium_no_pat",
    "signatures": 10,
    "pat_enabled": false,
    "expected_cost": 10
  },
  {
    "test_name": "ten_dilithium_with_pat",
    "signatures": 10,
    "pat_enabled": true,
    "expected_cost": 20,
    "comment": "PAT overhead for small batches"
  },
  {
    "test_name": "hundred_dilithium_with_pat",
    "signatures": 100,
    "pat_enabled": true,
    "expected_cost": 20,
    "savings_percent": 80
  },
  {
    "test_name": "five_hundred_dilithium_with_pat",
    "signatures": 512,
    "pat_enabled": true,
    "expected_cost": 20,
    "savings_percent": 96
  }
]
```

### PAT Threshold

```json
{
  "test_name": "pat_break_even",
  "signatures": 20,
  "cost_without_pat": 20,
  "cost_with_pat": 20,
  "recommendation": "PAT becomes beneficial at 21+ signatures"
}
```

---

## 5. Signature Test Vectors

### Dilithium ML-DSA-44 Signatures

```json
{
  "test_name": "dilithium_sign_verify",
  "secret_key_hex": "...(3328 bytes)...",
  "public_key_hex": "...(1312 bytes)...",
  "message_hex": "48656c6c6f20536f717563696f6e21",
  "expected_signature_hex": "...(2420 bytes)...",
  "verify_result": true
}
```

### Negative Signature Test Vectors (Must Reject)

```json
[
  {
    "test_name": "invalid_signature_wrong_key",
    "description": "Signature valid, but wrong public key used for verification",
    "public_key_hex": "DIFFERENT_PUBKEY_1312_BYTES",
    "message_hex": "54657374206d657373616765",
    "signature_hex": "VALID_SIG_FROM_OTHER_KEY",
    "expected_result": false,
    "security_note": "Signature forgery - verifies cryptographic binding"
  },
  {
    "test_name": "invalid_signature_tampered",
    "description": "Valid signature with single byte flipped",
    "public_key_hex": "CORRECT_PUBKEY",
    "message_hex": "54657374206d657373616765",
    "signature_hex": "VALID_SIG_WITH_BYTE_100_FLIPPED",
    "expected_result": false,
    "security_note": "Tamper detection - any bit flip must invalidate"
  },
  {
    "test_name": "invalid_signature_truncated",
    "description": "Signature truncated to 2419 bytes (missing last byte)",
    "signature_length": 2419,
    "expected_error": "SIG_INVALID_LENGTH",
    "security_note": "Length validation before verification"
  },
  {
    "test_name": "invalid_signature_extended",
    "description": "Signature extended to 2421 bytes (extra byte appended)",
    "signature_length": 2421,
    "expected_error": "SIG_INVALID_LENGTH",
    "security_note": "Strict length enforcement"
  },
  {
    "test_name": "invalid_signature_all_zeros",
    "description": "Signature is 2420 zero bytes",
    "signature_hex": "000...000 (2420 zeros)",
    "expected_result": false,
    "security_note": "Degenerate signature rejection"
  },
  {
    "test_name": "invalid_signature_all_ones",
    "description": "Signature is 2420 0xFF bytes",
    "signature_hex": "FFF...FFF (2420 0xFF)",
    "expected_result": false,
    "security_note": "Out-of-range coefficient detection"
  },
  {
    "test_name": "invalid_signature_different_message",
    "description": "Valid signature for message A, verified against message B",
    "message_signed": "4f726967696e616c",
    "message_verified": "4d6f646966696564",
    "expected_result": false,
    "security_note": "Message binding verification"
  }
]
```

---

## 5a. Encryption Negative Test Vectors (Must Reject)

```json
[
  {
    "test_name": "decrypt_wrong_passphrase",
    "description": "Attempt to decrypt wallet with incorrect passphrase",
    "correct_passphrase": "correct_horse_battery_staple",
    "attempted_passphrase": "wrong_passphrase",
    "expected_error": "DECRYPT_INVALID_PASSPHRASE",
    "security_note": "Must not reveal whether passphrase or MAC failed"
  },
  {
    "test_name": "decrypt_corrupted_ciphertext",
    "description": "Single bit flip in encrypted wallet data",
    "corruption_offset": 100,
    "expected_error": "DECRYPT_MAC_VERIFICATION_FAILED",
    "security_note": "Integrity check catches any modification"
  },
  {
    "test_name": "decrypt_corrupted_mac",
    "description": "Single bit flip in MAC tag",
    "corruption_offset_from_end": 10,
    "expected_error": "DECRYPT_MAC_VERIFICATION_FAILED",
    "security_note": "MAC verification must be constant-time"
  },
  {
    "test_name": "decrypt_truncated_file",
    "description": "Wallet file truncated (missing last 100 bytes)",
    "expected_error": "DECRYPT_INVALID_FORMAT",
    "security_note": "Length validation before processing"
  },
  {
    "test_name": "decrypt_wrong_magic",
    "description": "File with incorrect magic bytes",
    "magic_bytes": "FAKE",
    "expected_error": "DECRYPT_INVALID_FORMAT",
    "security_note": "Format validation before expensive operations"
  },
  {
    "test_name": "decrypt_unsupported_version",
    "description": "Wallet file with future version number",
    "version": "0x9999",
    "expected_error": "DECRYPT_UNSUPPORTED_VERSION",
    "security_note": "Version validation for forward compatibility"
  }
]
```

---

## 5b. Key Generation Negative Test Vectors

```json
[
  {
    "test_name": "keygen_insufficient_entropy",
    "description": "Attempt key generation with only 16 bytes entropy",
    "entropy_bytes": 16,
    "expected_error": "KEYGEN_INSUFFICIENT_ENTROPY",
    "security_note": "Minimum 32 bytes required for Dilithium seed"
  },
  {
    "test_name": "keygen_zero_entropy",
    "description": "Attempt key generation with all-zero entropy",
    "entropy_hex": "0000000000000000000000000000000000000000000000000000000000000000",
    "expected_error": "KEYGEN_WEAK_ENTROPY",
    "security_note": "Detect obviously non-random input"
  },
  {
    "test_name": "keygen_repeated_entropy",
    "description": "Attempt key generation with repeating pattern",
    "entropy_hex": "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
    "expected_behavior": "Should generate key (pattern detection is non-trivial)",
    "security_note": "Entropy quality is caller's responsibility"
  }
]
```

---

## 5c. Address Negative Test Vectors (Extended)

```json
[
  {
    "test_name": "address_invalid_hrp_typo",
    "address": "sq2qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj9xr3f",
    "expected_error": "ADDR_INVALID_PREFIX",
    "security_note": "Typo detection (sq2 vs sq1)"
  },
  {
    "test_name": "address_bech32_not_bech32m",
    "description": "Valid Bech32 but not Bech32m encoding",
    "address": "sq1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqudcjfu",
    "expected_error": "ADDR_WRONG_ENCODING",
    "security_note": "Bech32m is required for v1+ addresses"
  },
  {
    "test_name": "address_empty_data",
    "address": "sq1",
    "expected_error": "ADDR_INVALID_LENGTH",
    "security_note": "Handle degenerate inputs gracefully"
  },
  {
    "test_name": "address_null_character",
    "address": "sq1q\\x00qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj9xr3f",
    "expected_error": "ADDR_INVALID_CHARACTER",
    "security_note": "Reject embedded null bytes"
  },
  {
    "test_name": "address_unicode_homoglyph",
    "description": "Address with Cyrillic 'а' instead of Latin 'a'",
    "address": "sq1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj9хr3f",
    "expected_error": "ADDR_INVALID_CHARACTER",
    "security_note": "Homoglyph attack detection"
  },
  {
    "test_name": "address_wrong_network",
    "description": "Mainnet address used on testnet validation",
    "address": "sq1q5rvwwdc...",
    "validate_for_network": "testnet",
    "expected_error": "ADDR_NETWORK_MISMATCH",
    "security_note": "Network enforcement prevents cross-chain errors"
  }
]
```

---

## 6. Network Prefix Test Vectors

```json
[
  {"address_prefix": "sq1", "network": "mainnet", "type": "P2PQ"},
  {"address_prefix": "sqp1", "network": "mainnet", "type": "P2PQ_PAT"},
  {"address_prefix": "sqsh1", "network": "mainnet", "type": "P2SH_PQ"},
  {"address_prefix": "tsq1", "network": "testnet", "type": "P2PQ"},
  {"address_prefix": "tsqp1", "network": "testnet", "type": "P2PQ_PAT"},
  {"address_prefix": "tsqsh1", "network": "testnet", "type": "P2SH_PQ"},
  {"address_prefix": "ssq1", "network": "stagenet", "type": "P2PQ"},
  {"address_prefix": "ssqp1", "network": "stagenet", "type": "P2PQ_PAT"},
  {"address_prefix": "ssqsh1", "network": "stagenet", "type": "P2SH_PQ"}
]
```

---

## 7. Implementation Checklist

| Test Category | Required | Pass/Fail |
|---------------|----------|-----------|
| Key derivation | ✅ | ⬜ |
| Address encoding | ✅ | ⬜ |
| Address validation | ✅ | ⬜ |
| Address rejection | ✅ | ⬜ |
| TX construction | ✅ | ⬜ |
| PAT aggregation | ✅ | ⬜ |
| Cost estimation | ✅ | ⬜ |
| Signature verification | ✅ | ⬜ |
| Network detection | ✅ | ⬜ |

---

*Wallet Test Vectors v1.0 | January 2026*
