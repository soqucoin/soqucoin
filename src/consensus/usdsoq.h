// Copyright (c) 2024-2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-AUD2-002: USDSOQ Stablecoin Consensus Layer
// Design Log: DL-USDSOQ-STABLECOIN.md
//
// USDSOQ is a fiat-reserve 1:1 USD-backed stablecoin issued natively on the
// Soqucoin L1. Minting, burning, freezing, and authority rotation are
// controlled by a Foundation-managed Dilithium M-of-N multisig.
//
// All operations are BIP9-gated via DEPLOYMENT_USDSOQ (bit 6) and are
// NEVER_ACTIVE on mainnet at genesis. Activation requires miner signaling.
//
// Wire format: CTxOut.nAssetType == ASSET_TYPE_USDSOQ (0x01)

#ifndef SOQUCOIN_CONSENSUS_USDSOQ_H
#define SOQUCOIN_CONSENSUS_USDSOQ_H

#include "amount.h"
#include "serialize.h"

#include <cstdint>
#include <vector>

// =========================================================================
// Asset type constants — shared between USDSOQ and privacy layers
// =========================================================================
static constexpr uint8_t ASSET_TYPE_SOQ    = 0x00;  // Native SOQ
static constexpr uint8_t ASSET_TYPE_USDSOQ = 0x01;  // USDSOQ stablecoin

// Maximum valid asset type (for field validation in CheckTransaction)
static constexpr uint8_t ASSET_TYPE_MAX    = 0x01;

// =========================================================================
// Visibility mode constants — shared between USDSOQ and privacy layers
// =========================================================================
static constexpr uint8_t VISIBILITY_TRANSPARENT  = 0x00;  // Default: cleartext amounts
static constexpr uint8_t VISIBILITY_CONFIDENTIAL = 0x01;  // Lattice-BP++ hidden amounts

// FROZEN UTXO: high bit of nVisibility encodes freeze status.
// This allows frozen+transparent (0x80) and frozen+confidential (0x81).
// The low bits still indicate the visibility mode.
// GENIUS Act §4(a)(2) compliance: stablecoin issuers must be able to freeze.
static constexpr uint8_t VISIBILITY_FROZEN_MASK   = 0x80;

// Maximum valid visibility mode (excluding frozen flag)
static constexpr uint8_t VISIBILITY_MAX          = 0x01;

// Short aliases for validation.cpp/ConnectBlock readability
static constexpr uint8_t ASSET_SOQ    = ASSET_TYPE_SOQ;
static constexpr uint8_t ASSET_USDSOQ = ASSET_TYPE_USDSOQ;

// =========================================================================
// Authority configuration limits
// =========================================================================

//! Maximum number of authority keys in the M-of-N set
static constexpr uint32_t USDSOQ_MAX_AUTHORITY_KEYS = 15;

//! Minimum threshold for M-of-N (at least 2-of-N for security)
static constexpr uint32_t USDSOQ_MIN_THRESHOLD = 2;

//! Dilithium ML-DSA-44 public key size (NIST FIPS 204)
static constexpr size_t DILITHIUM_PUBKEY_SIZE = 1312;

//! Dilithium ML-DSA-44 signature size (NIST FIPS 204)
static constexpr size_t DILITHIUM_SIG_SIZE = 2420;

// =========================================================================
// CUSDSOQSupply — Deterministic supply counter
// =========================================================================
// Tracks total_minted and total_burned atomically in chainstate.
// Outstanding() = total_minted - total_burned.
// Invariant: Outstanding() >= 0 at all times.
// Verified during -reindex by replaying all MINT/BURN transactions.

class CUSDSOQSupply
{
private:
    CAmount total_minted;
    CAmount total_burned;

public:
    CUSDSOQSupply() : total_minted(0), total_burned(0) {}

    //! Current outstanding USDSOQ supply
    CAmount Outstanding() const { return total_minted - total_burned; }

    //! Total ever minted
    CAmount TotalMinted() const { return total_minted; }

    //! Total ever burned
    CAmount TotalBurned() const { return total_burned; }

    //! Record a mint operation. Returns false on overflow.
    //! SECURITY: Uses checked arithmetic to prevent supply inflation attacks.
    bool Mint(CAmount amount);

    //! Record a burn operation. Returns false on underflow.
    //! SECURITY: Prevents burning more than outstanding supply.
    bool Burn(CAmount amount);

    //! Verify the supply invariant: Outstanding() >= 0 and both counters
    //! are within valid MoneyRange bounds.
    bool CheckInvariant() const;

    //! Reset to initial state (for -reindex)
    void Reset() { total_minted = 0; total_burned = 0; }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(total_minted);
        READWRITE(total_burned);
    }
};

// =========================================================================
// CUSDSOQAuthority — M-of-N Dilithium authority key management
// =========================================================================
// The authority key set controls all privileged USDSOQ operations:
//   - MINT: Create new USDSOQ supply
//   - BURN: Destroy USDSOQ supply
//   - FREEZE: Mark a UTXO as frozen (GENIUS Act compliance)
//   - ROTATE_AUTHORITY: Replace the authority key set
//
// At genesis, the key set is empty. Keys are injected during BIP9 activation
// via the deployment parameters in chainparams.cpp.

class CUSDSOQAuthority
{
private:
    //! Ordered set of Dilithium ML-DSA-44 public keys
    std::vector<std::vector<uint8_t>> authority_keys;

    //! Required number of signatures (M in M-of-N)
    uint32_t threshold;

public:
    CUSDSOQAuthority() : threshold(0) {}

    //! Initialize with a key set and threshold
    bool Initialize(const std::vector<std::vector<uint8_t>>& keys, uint32_t m);

    //! Verify that at least M-of-N valid Dilithium signatures exist for msg.
    //! SECURITY: Constant-time signature count accumulation to prevent
    //! timing-based threshold inference attacks.
    bool VerifyAuthoritySignatures(
        const std::vector<uint8_t>& msg,
        const std::vector<std::vector<uint8_t>>& sigs) const;

    //! Rotate to a new authority key set. Requires existing M-of-N authorization.
    //! The rotation message covers both old and new key sets to prevent replay.
    bool RotateKeys(const std::vector<std::vector<uint8_t>>& new_keys,
                    uint32_t new_threshold);

    //! Get current threshold
    uint32_t GetThreshold() const { return threshold; }

    //! Get number of authority keys
    size_t GetKeyCount() const { return authority_keys.size(); }

    //! Check if authority is initialized (has keys)
    bool IsInitialized() const { return !authority_keys.empty() && threshold > 0; }

    //! Get a read-only reference to the key set
    const std::vector<std::vector<uint8_t>>& GetKeys() const { return authority_keys; }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(authority_keys);
        READWRITE(threshold);
    }
};

#endif // SOQUCOIN_CONSENSUS_USDSOQ_H
