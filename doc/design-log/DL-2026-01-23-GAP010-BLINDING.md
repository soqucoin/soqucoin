# Design Log: GAP-010 Blinding Factor Deterministic Derivation

> **Log ID**: DL-2026-01-23-GAP010-BLINDING
> **Author**: Casey (Founder)
> **Date**: January 23, 2026
> **Status**: PROPOSED (Awaiting Review)
> **Priority**: MEDIUM (Privacy features activate Stage 2, block 100,000)

---

## Background

During gap verification on January 23, 2026, we discovered that blinding factors for Bulletproofs++ confidential transactions are generated using random bytes rather than deterministic HKDF derivation from the wallet seed.

**Current Implementation** (`src/wallet/rpcwallet.cpp:347-349`):
```cpp
// 1. Generate blinding factor
uint256 blinding;
GetStrongRandBytes(blinding.begin(), 32);  // ❌ RANDOM - NOT RECOVERABLE
```

**The Problem**: If a user restores their wallet from a BIP-39 seed, they can recover:
- ✅ All spending keys (Dilithium)
- ✅ All addresses
- ❌ **NOT** the blinding factors for privacy transactions

**Impact**: Privacy transaction outputs **cannot be spent** after wallet restoration because the blinding factor is required to create the spending proof.

---

## Existing Infrastructure

The codebase already has HKDF infrastructure for deterministic key derivation:

### 1. HKDF Function (`src/crypto/latticebp/commitment.cpp:16`)
```cpp
void HKDF_SHA256(
    const uint8_t* ikm, size_t ikm_len,     // Input key material (seed)
    const uint8_t* salt, size_t salt_len,   // Salt (domain separation)
    const uint8_t* info, size_t info_len,   // Info (context)
    uint8_t* okm, size_t okm_len            // Output key material
);
```

### 2. Domain Separation Pattern (`src/crypto/latticebp/stealth_address.h:51-78`)
```cpp
// Already using HKDF with domain separation:
ViewKey::deriveFromSeed(seed, "soqucoin.privacy.view.v1");
SpendKey::deriveFromSeed(seed, "soqucoin.privacy.spend.v1");
```

### 3. Key Derivation Diagram (Existing)
```
Master Seed (256 bits from BIP-39)
       │
       ▼
   HKDF Master Key
       │
       ├─→ HKDF("spending")  → Spending Key Chain
       ├─→ HKDF("blinding")  → ❓ NOT IMPLEMENTED
       ├─→ HKDF("staking")   → Future Use
       └─→ HKDF("L2")        → Lightning Keys
```

---

## Proposed Solution

### Design: Deterministic Blinding Factor Derivation

Add a new derivation path that generates blinding factors deterministically:

```
Master Seed
    │
    ├─→ HKDF("soqucoin.blinding.v1") → Blinding Factor Chain
    │       │
    │       ├─→ HKDF(address_index || output_index) → Unique Blinding Factor
```

### Key Insight: Use Address Index + Output Index

Each blinding factor must be:
1. **Unique per output** - Reuse = catastrophic privacy failure
2. **Deterministic** - Same seed + same parameters = same blinding
3. **Non-reversible** - Cannot derive seed from blinding factor

**Formula**:
```
blinding[i] = HKDF(
    ikm  = master_seed,
    salt = "soqucoin.blinding.v1",
    info = address_index || output_index || tx_nonce
)
```

Where:
- `address_index` = BIP-44 style index of the sending address
- `output_index` = Sequential counter for outputs from this address
- `tx_nonce` = Transaction creation timestamp (prevents replay across wallets)

---

## Implementation Plan

### Phase 1: Add Blinding Factor Derivation (2-3 hours)

#### File: `src/wallet/blindingkeys.h` [NEW]

```cpp
#ifndef SOQUCOIN_WALLET_BLINDINGKEYS_H
#define SOQUCOIN_WALLET_BLINDINGKEYS_H

#include <crypto/latticebp/commitment.h>
#include <uint256.h>
#include <cstdint>

/**
 * Deterministic blinding factor derivation for privacy transactions.
 * 
 * Blinding factors are derived from the wallet master seed using HKDF,
 * ensuring they can be recovered from a seed backup.
 */
class CBlindingKeyChain
{
private:
    std::array<uint8_t, 32> m_chain_seed;
    uint64_t m_next_index;

public:
    // Domain separation constant
    static constexpr const char* DOMAIN = "soqucoin.blinding.v1";

    // Initialize from wallet master seed
    CBlindingKeyChain(const std::array<uint8_t, 32>& master_seed);

    /**
     * Derive unique blinding factor for a specific output.
     *
     * @param address_index  Index of the sending address in HD chain
     * @param output_index   Index of this output for the address
     * @param tx_timestamp   Transaction creation timestamp (nonce)
     * @return 32-byte blinding factor
     */
    uint256 DeriveBlindingFactor(
        uint32_t address_index,
        uint32_t output_index,
        int64_t tx_timestamp
    );

    /**
     * Get next blinding factor (auto-increments index).
     * Use for new outputs; stores index in wallet database.
     */
    uint256 GetNextBlindingFactor(uint32_t address_index, int64_t tx_timestamp);

    // Persist chain state to wallet database
    bool SaveToDatabase(CWalletDB& db);
    bool LoadFromDatabase(CWalletDB& db);
};

#endif // SOQUCOIN_WALLET_BLINDINGKEYS_H
```

#### File: `src/wallet/blindingkeys.cpp` [NEW]

```cpp
#include "blindingkeys.h"
#include <crypto/sha256.h>

// External HKDF from latticebp
extern void HKDF_SHA256(
    const uint8_t* ikm, size_t ikm_len,
    const uint8_t* salt, size_t salt_len,
    const uint8_t* info, size_t info_len,
    uint8_t* okm, size_t okm_len
);

CBlindingKeyChain::CBlindingKeyChain(const std::array<uint8_t, 32>& master_seed)
    : m_next_index(0)
{
    // Derive chain-specific seed from master
    HKDF_SHA256(
        master_seed.data(), 32,
        reinterpret_cast<const uint8_t*>(DOMAIN), strlen(DOMAIN),
        nullptr, 0,
        m_chain_seed.data(), 32
    );
}

uint256 CBlindingKeyChain::DeriveBlindingFactor(
    uint32_t address_index,
    uint32_t output_index,
    int64_t tx_timestamp)
{
    // Build unique derivation info: address_index || output_index || timestamp
    uint8_t info[16];
    memcpy(info, &address_index, 4);
    memcpy(info + 4, &output_index, 4);
    memcpy(info + 8, &tx_timestamp, 8);

    uint256 blinding;
    HKDF_SHA256(
        m_chain_seed.data(), 32,
        reinterpret_cast<const uint8_t*>("output"), 6,
        info, 16,
        blinding.begin(), 32
    );

    return blinding;
}

uint256 CBlindingKeyChain::GetNextBlindingFactor(
    uint32_t address_index,
    int64_t tx_timestamp)
{
    return DeriveBlindingFactor(address_index, m_next_index++, tx_timestamp);
}
```

---

### Phase 2: Integrate with Wallet (1-2 hours)

#### Modify: `src/wallet/rpcwallet.cpp`

**Before** (lines 347-349):
```cpp
// 1. Generate blinding factor
uint256 blinding;
GetStrongRandBytes(blinding.begin(), 32);
```

**After**:
```cpp
// 1. Generate deterministic blinding factor from wallet seed
uint256 blinding;
if (pwalletMain->GetBlindingKeyChain()) {
    // Deterministic derivation - recoverable from seed
    uint32_t addrIndex = /* get from address book */;
    int64_t txTimestamp = GetTime();
    blinding = pwalletMain->GetBlindingKeyChain()->GetNextBlindingFactor(
        addrIndex, txTimestamp
    );
} else {
    // Fallback for legacy wallets without HD seed
    GetStrongRandBytes(blinding.begin(), 32);
    LogPrintf("WARNING: Using non-recoverable random blinding factor\n");
}
```

---

### Phase 3: Wallet Database Schema (1 hour)

#### Add to `src/wallet/walletdb.h`:

```cpp
// Store blinding key chain state
bool WriteBlindingKeyState(const uint256& chain_seed, uint64_t next_index);
bool ReadBlindingKeyState(uint256& chain_seed, uint64_t& next_index);
```

#### Add to `src/wallet/wallet.h`:

```cpp
// Blinding key chain for privacy transactions
std::unique_ptr<CBlindingKeyChain> m_blinding_keys;

CBlindingKeyChain* GetBlindingKeyChain() { return m_blinding_keys.get(); }
void InitBlindingKeys(); // Called during wallet load/creation
```

---

### Phase 4: Wallet Recovery Support (1-2 hours)

When restoring from seed, regenerate blinding factors by:

1. **Scan blockchain** for privacy outputs belonging to wallet
2. For each output found:
   - Extract `address_index` from address
   - Extract `output_index` from on-chain counter or transaction order
   - Rederive blinding factor using same formula
3. **Store recovered blinding factors** in wallet database

This is already how spending keys work - blinding factors follow the same pattern.

---

## Trade-offs

| Decision | Trade-off | Rationale |
|----------|-----------|-----------|
| HKDF vs. ChaCha20 | HKDF slower but more standard | Matches existing codebase pattern |
| Per-output derivation | More complex than per-TX | Required for privacy (unique blinding per output) |
| Timestamp as nonce | Requires timestamp storage | Prevents accidental reuse across wallet restores |

---

## Security Considerations

### ✅ Correct Properties:
1. **Unique blinding factors** - address_index + output_index guarantees uniqueness
2. **Deterministic recovery** - Same seed always produces same factors
3. **Domain separation** - Blinding chain cannot derive spending keys

### ⚠️ Attack Mitigations:
1. **Blinding factor reuse** = complete privacy failure
   - Mitigation: Enforce monotonic output counter, never reuse
2. **Timestamp manipulation** = could cause blinding collisions
   - Mitigation: Store timestamp in wallet DB, check for duplicates

---

## Testing Plan

### Unit Tests (`src/test/blindingkeys_tests.cpp`)

```cpp
BOOST_AUTO_TEST_CASE(deterministic_derivation)
{
    // Same seed → same blinding factor
    std::array<uint8_t, 32> seed;
    GetStrongRandBytes(seed.data(), 32);
    
    CBlindingKeyChain chain1(seed);
    CBlindingKeyChain chain2(seed);
    
    uint256 bf1 = chain1.DeriveBlindingFactor(0, 0, 1000);
    uint256 bf2 = chain2.DeriveBlindingFactor(0, 0, 1000);
    
    BOOST_CHECK(bf1 == bf2);
}

BOOST_AUTO_TEST_CASE(unique_per_output)
{
    // Different output_index → different blinding factor
    std::array<uint8_t, 32> seed;
    GetStrongRandBytes(seed.data(), 32);
    
    CBlindingKeyChain chain(seed);
    
    uint256 bf1 = chain.DeriveBlindingFactor(0, 0, 1000);
    uint256 bf2 = chain.DeriveBlindingFactor(0, 1, 1000);
    
    BOOST_CHECK(bf1 != bf2);
}
```

### Integration Test

1. Create wallet with HD seed
2. Send privacy transaction
3. Delete wallet files
4. Restore from seed
5. **Verify**: Can spend the privacy outputs

---

## Timeline

| Phase | Estimate | Owner |
|-------|----------|-------|
| 1. CBlindingKeyChain class | 2-3 hours | Casey/Archith |
| 2. Wallet integration | 1-2 hours | Casey |
| 3. Database schema | 1 hour | Casey |
| 4. Recovery support | 1-2 hours | Casey |
| 5. Testing | 2 hours | Casey |
| **Total** | **7-10 hours** | |

---

## Questions for Team

1. **@Archith**: Should we use the same HKDF from latticebp or create a dedicated crypto utility?

2. **@All**: Do we need backward compatibility for existing testnet privacy TXs (probably not - we can require re-creating them)?

3. **@John**: Any security concerns with the derivation scheme?

---

## References

- [HKDF RFC 5869](https://tools.ietf.org/html/rfc5869)
- [BIP-32 Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [Monero Stealth Address Derivation](https://www.getmonero.org/resources/moneropedia/stealthaddress.html)
- Soqucoin HKDF Domain Separation: `doc/design-log/HKDF_DOMAIN_SEPARATION.md`

---

*Pending Approval: Casey Wilson, Dr. Archith Rayabharam, John Fastiggi*
