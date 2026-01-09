# Soqucoin Address Format Specification

> **Version**: 1.0 | **Updated**: 2026-01-06
> **Status**: Specification
> **Audience**: Wallet Developers, Exchanges, Auditors

---

## Overview

Soqucoin uses a post-quantum address format based on Dilithium public key hashes. This specification defines encoding, validation, and compatibility requirements.

---

## Address Types

| Type | Prefix (Mainnet) | Prefix (Testnet) | Prefix (Stagenet) | Description |
|------|------------------|------------------|-------------------|-------------|
| **P2PQ** | `sq1` | `tsq1` | `ssq1` | Pay-to-Post-Quantum (standard) |
| **P2PQ-PAT** | `sqp1` | `tsqp1` | `ssqp1` | P2PQ with PAT aggregation hint |
| **P2SH-PQ** | `sqsh1` | `tsqsh1` | `ssqsh1` | Script hash (post-quantum) |

---

## Encoding Specification

### P2PQ Address (Standard)

```
Format: <prefix><version><pubkey_hash><checksum>

Components:
- Prefix:       "sq1" (mainnet), "tsq1" (testnet), "ssq1" (stagenet)
- Version:      1 byte (0x00 for v1)
- PubkeyHash:   20 bytes (BLAKE2b-160 of Dilithium public key)
- Checksum:     4 bytes (first 4 bytes of BLAKE2b(prefix + version + hash))

Encoding:     Bech32m
Total Length: ~52 characters (mainnet)
```

### Why BLAKE2b-160?

| Property | BLAKE2b-160 | SHA-256 | Rationale |
|----------|-------------|---------|----------|
| **Speed** | ~3-5x faster | Baseline | Dilithium pubkeys are 1,312 bytes; speed matters |
| **Output size** | 160 bits (20 bytes) | 256 bits (32 bytes) | 12 bytes saved per address |
| **Collision resistance** | 80 bits | 128 bits | Sufficient for address uniqueness (birthday bound) |
| **Preimage resistance** | 160 bits | 256 bits | Address recovery still infeasible |
| **Quantum security** | ~80 bits (Grover) | ~128 bits | Acceptable for address hashing (not signing) |
| **L2 compatibility** | HKDF-BLAKE2b | — | Consistent with channel key derivation |

### Derivation

```
1. Generate Dilithium-ML-DSA-44 keypair (1,312-byte public key)
2. pubkey_hash = BLAKE2b(pubkey, output_len=20)  // 160 bits
3. version = 0x00
4. checksum = BLAKE2b("sq1" || version || pubkey_hash, output_len=4)[0:4]
5. address = Bech32m_Encode("sq1", version || pubkey_hash || checksum)
```

> **Security Note**: 160-bit hashes provide 80-bit collision resistance via birthday bound.
> For address generation, this is acceptable as finding two Dilithium keypairs that
> hash to the same address requires ~2^80 operations, far exceeding practical attack
> budgets. The signing keys themselves retain full ML-DSA-44 security (NIST Level 2).

---

## Example Addresses

### Mainnet

```
Standard P2PQ:
sq1qw508d6qejxtdg4y5r3zarvaryvgpjf0v8t9xq3k2y9hj6k...

P2PQ with PAT hint:
sqp1qw508d6qejxtdg4y5r3zarvaryvgpjf0v8t9xq3k2y9hj6...
```

### Testnet

```
Standard P2PQ:
tsq1qw508d6qejxtdg4y5r3zarvaryvgpjf0v8t9xq3k2y9hj6...
```

### Stagenet

```
Standard P2PQ:
ssq1qw508d6qejxtdg4y5r3zarvaryvgpjf0v8t9xq3k2y9hj6...
```

---

## Validation Rules

### Required Checks

```cpp
bool ValidateAddress(const std::string& address) {
    // 1. Check prefix
    if (!StartsWithValidPrefix(address)) return false;
    
    // 2. Decode Bech32m
    auto decoded = Bech32mDecode(address);
    if (!decoded.valid) return false;
    
    // 3. Check version byte
    if (decoded.data[0] > MAX_VERSION) return false;
    
    // 4. Check hash length (32 bytes)
    if (decoded.data.size() != 1 + 32 + 4) return false;
    
    // 5. Verify checksum
    auto expected = ComputeChecksum(decoded.prefix, decoded.data.substr(0, 33));
    if (decoded.data.substr(33, 4) != expected) return false;
    
    return true;
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `ADDR_OK` | Valid address |
| `ADDR_INVALID_PREFIX` | Unknown network prefix |
| `ADDR_INVALID_ENCODING` | Bech32m decode failed |
| `ADDR_INVALID_VERSION` | Unsupported version byte |
| `ADDR_INVALID_LENGTH` | Wrong hash length |
| `ADDR_INVALID_CHECKSUM` | Checksum mismatch |

---

## Network Detection

```cpp
Network DetectNetwork(const std::string& address) {
    if (address.starts_with("sq1") || address.starts_with("sqp1") || 
        address.starts_with("sqsh1")) {
        return Network::Mainnet;
    }
    if (address.starts_with("tsq1") || address.starts_with("tsqp1") || 
        address.starts_with("tsqsh1")) {
        return Network::Testnet;
    }
    if (address.starts_with("ssq1") || address.starts_with("ssqp1") || 
        address.starts_with("ssqsh1")) {
        return Network::Stagenet;
    }
    return Network::Unknown;
}
```

---

## BIP-44 Derivation Path

Soqucoin uses coin type **21329** (0x5351 in hex, matching Chain ID):

```
m / purpose' / coin_type' / account' / change / address_index

Standard path: m/44'/21329'/0'/0/0
Change path:   m/44'/21329'/0'/1/0
```

---

## Compatibility Notes

### Exchange Integration

| Requirement | Implementation |
|-------------|----------------|
| Address validation | Use Bech32m library with custom prefix |
| Network detection | Check prefix (sq1/tsq1/ssq1) |
| Display | Full address, no truncation |
| QR codes | Standard QR with address string |

### Wallet Interoperability

| Feature | Support |
|---------|---------|
| Bech32m encoding | ✅ Required |
| Case insensitivity | ✅ Bech32m standard |
| Legacy formats | ❌ Not supported |
| SegWit-style | ❌ Different PQ format |

---

## Test Vectors

### Valid Addresses

```json
{
  "mainnet_p2pq": {
    "pubkey_hex": "a1b2c3d4...",
    "address": "sq1q0k...(full address)",
    "valid": true
  },
  "testnet_p2pq": {
    "pubkey_hex": "a1b2c3d4...",
    "address": "tsq1q0k...",
    "valid": true
  }
}
```

### Invalid Addresses (Must Reject)

```json
{
  "wrong_checksum": {
    "address": "sq1q0k...modified",
    "error": "ADDR_INVALID_CHECKSUM"
  },
  "wrong_length": {
    "address": "sq1qshort",
    "error": "ADDR_INVALID_LENGTH"
  },
  "unknown_prefix": {
    "address": "xyz1q0k...",
    "error": "ADDR_INVALID_PREFIX"
  }
}
```

---

## Security Considerations

| Concern | Mitigation |
|---------|------------|
| Address reuse | Wallets should generate new addresses per TX |
| Typosquatting | Checksum catches most typos |
| Cross-network | Prefix prevents mainnet/testnet confusion |
| Quantum safety | SHA3-256 + Dilithium provides PQ resistance |

---

## Implementation Checklist

For wallet developers:

- [ ] Implement Bech32m encoding/decoding
- [ ] Implement BLAKE2b-160 hashing (RFC 7693)
- [ ] Implement network prefix detection
- [ ] Implement checksum calculation
- [ ] Add all test vectors
- [ ] Test cross-network rejection

---

*Address Format Specification v1.0 | January 2026*
