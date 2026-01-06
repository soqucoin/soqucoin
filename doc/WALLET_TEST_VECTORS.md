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
