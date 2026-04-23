// Copyright (c) 2024-2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-AUD2-002: USDSOQ Stablecoin Consensus Layer — Implementation
// See consensus/usdsoq.h for design documentation.

#include "consensus/usdsoq.h"
#include "amount.h"
#include "crypto/sha256.h"
extern "C" {
#include "crypto/dilithium/api.h"
}
#include "hash.h"

#include <algorithm>
#include <limits>

// =========================================================================
// CUSDSOQSupply — Checked arithmetic supply counter
// =========================================================================

bool CUSDSOQSupply::Mint(CAmount amount)
{
    // SECURITY: Reject non-positive mint amounts
    if (amount <= 0) return false;

    // SECURITY: Checked addition — prevent supply inflation via overflow
    if (amount > std::numeric_limits<CAmount>::max() - total_minted) return false;
    CAmount new_minted = total_minted + amount;

    // SECURITY: Verify MoneyRange on the new total
    if (!MoneyRange(new_minted)) return false;

    // SECURITY: Verify the resulting outstanding supply is valid
    CAmount new_outstanding = new_minted - total_burned;
    if (!MoneyRange(new_outstanding)) return false;

    total_minted = new_minted;
    return true;
}

bool CUSDSOQSupply::Burn(CAmount amount)
{
    // SECURITY: Reject non-positive burn amounts
    if (amount <= 0) return false;

    // SECURITY: Checked addition — prevent underflow bypass
    if (amount > std::numeric_limits<CAmount>::max() - total_burned) return false;
    CAmount new_burned = total_burned + amount;

    // SECURITY: Cannot burn more than was minted
    if (new_burned > total_minted) return false;

    // SECURITY: Verify MoneyRange on the new total
    if (!MoneyRange(new_burned)) return false;

    total_burned = new_burned;
    return true;
}

bool CUSDSOQSupply::CheckInvariant() const
{
    // Both counters must be non-negative
    if (total_minted < 0 || total_burned < 0) return false;

    // Cannot have burned more than minted
    if (total_burned > total_minted) return false;

    // Both counters must be in valid MoneyRange
    if (!MoneyRange(total_minted)) return false;
    if (!MoneyRange(total_burned)) return false;

    // Outstanding must also be in valid range
    CAmount outstanding = total_minted - total_burned;
    if (!MoneyRange(outstanding)) return false;

    return true;
}

// =========================================================================
// CUSDSOQAuthority — M-of-N Dilithium key management
// =========================================================================

bool CUSDSOQAuthority::Initialize(
    const std::vector<std::vector<uint8_t>>& keys, uint32_t m)
{
    // Validate threshold bounds
    if (keys.empty()) return false;
    if (keys.size() > USDSOQ_MAX_AUTHORITY_KEYS) return false;
    if (m < USDSOQ_MIN_THRESHOLD) return false;
    if (m > keys.size()) return false;

    // Validate all keys are correct size (ML-DSA-44 = 1312 bytes)
    for (const auto& key : keys) {
        if (key.size() != DILITHIUM_PUBKEY_SIZE) return false;
    }

    // Check for duplicate keys — each authority key must be unique
    // O(N^2) is fine for N <= 15
    for (size_t i = 0; i < keys.size(); ++i) {
        for (size_t j = i + 1; j < keys.size(); ++j) {
            if (keys[i] == keys[j]) return false;
        }
    }

    authority_keys = keys;
    threshold = m;
    return true;
}

bool CUSDSOQAuthority::VerifyAuthoritySignatures(
    const std::vector<uint8_t>& msg,
    const std::vector<std::vector<uint8_t>>& sigs) const
{
    if (!IsInitialized()) return false;
    if (sigs.empty()) return false;
    if (sigs.size() > authority_keys.size()) return false;

    // SECURITY: Validate all signature sizes before any verification
    for (const auto& sig : sigs) {
        if (sig.size() != DILITHIUM_SIG_SIZE) return false;
    }

    // Count valid signatures across the authority key set.
    // Each key may produce at most one valid signature.
    // We use a bitvector to track which keys have been matched,
    // preventing double-counting if the same key appears twice
    // in the sigs array (it shouldn't, but defense-in-depth).
    std::vector<bool> key_used(authority_keys.size(), false);
    uint32_t valid_count = 0;

    for (const auto& sig : sigs) {
        for (size_t k = 0; k < authority_keys.size(); ++k) {
            if (key_used[k]) continue;

            // Dilithium verification: FIPS 204 ML-DSA-44
            // Empty context (nullptr, 0) — domain separation is in the msg
            int result = pqcrystals_dilithium2_ref_verify(
                sig.data(), sig.size(),
                msg.data(), msg.size(),
                nullptr, 0,  // FIPS 204 context string (empty)
                authority_keys[k].data());

            if (result == 0) {  // 0 = success in CRYSTALS-Dilithium
                key_used[k] = true;
                ++valid_count;
                break;  // This sig matched a key, move to next sig
            }
        }
    }

    // SECURITY: Threshold check — must have at least M valid sigs
    return valid_count >= threshold;
}

bool CUSDSOQAuthority::RotateKeys(
    const std::vector<std::vector<uint8_t>>& new_keys,
    uint32_t new_threshold)
{
    // Validate the new key set using the same rules as Initialize
    if (new_keys.empty()) return false;
    if (new_keys.size() > USDSOQ_MAX_AUTHORITY_KEYS) return false;
    if (new_threshold < USDSOQ_MIN_THRESHOLD) return false;
    if (new_threshold > new_keys.size()) return false;

    // Validate all new keys are correct size
    for (const auto& key : new_keys) {
        if (key.size() != DILITHIUM_PUBKEY_SIZE) return false;
    }

    // Check for duplicate keys in new set
    for (size_t i = 0; i < new_keys.size(); ++i) {
        for (size_t j = i + 1; j < new_keys.size(); ++j) {
            if (new_keys[i] == new_keys[j]) return false;
        }
    }

    // Note: Authorization (M-of-N signature verification on the rotation
    // message) is performed by the OP_USDSOQ_ROTATE handler in EvalScript,
    // not here. This method only updates the state after authorization
    // has been verified.
    authority_keys = new_keys;
    threshold = new_threshold;
    return true;
}
