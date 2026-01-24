// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_WALLET_PQDERIVE_H
#define SOQUCOIN_WALLET_PQDERIVE_H

/**
 * @file pqderive.h
 * @brief HKDF-based key derivation utilities for Dilithium
 *
 * This file provides the implementation for key derivation functions
 * that support the DerivationPath struct defined in pqkeys.h.
 *
 * Per Whitepaper Section 10: "Why HKDF Instead of BIP-32?"
 * - HKDF-SHA256 is used (NIST SP 800-56C approved)
 * - Domain separation for L2 forward compatibility
 *
 * @see pqkeys.h for DerivationPath struct and PQKeyPair::DeriveFromSeed()
 */

#include "pqkeys.h"
#include <array>
#include <string>
#include <vector>

namespace soqucoin
{
namespace pqwallet
{

// Domain separators for different key types (per whitepaper Section 10.4)
extern const std::string DOMAIN_WALLET;     // "soqucoin-pqwallet-v1"
extern const std::string DOMAIN_BLINDING;   // "soqucoin-blinding-v1"
extern const std::string DOMAIN_CHANNEL;    // "soqucoin-v1/channel"
extern const std::string DOMAIN_WATCHTOWER; // "soqucoin-v1/watchtower"

/**
 * @brief Derive raw 32-byte key material using HKDF-SHA256
 *
 * @param masterSeed 64-byte BIP-39 derived seed
 * @param path BIP-44 derivation path
 * @param domain Domain separator string
 * @return 32-byte derived key material
 */
std::array<uint8_t, 32> DeriveKeyMaterial(
    const SecureBytes& masterSeed,
    const DerivationPath& path,
    const std::string& domain);

/**
 * @brief Derive blinding factor for privacy transactions (GAP-010)
 *
 * Uses DOMAIN_BLINDING to ensure signing keys and blinding factors
 * are derived independently.
 *
 * @param masterSeed 64-byte BIP-39 derived seed
 * @param outputIndex Index of the privacy output
 * @return 32-byte blinding factor
 */
std::array<uint8_t, 32> DeriveBlindingFactor(
    const SecureBytes& masterSeed,
    uint64_t outputIndex);

/**
 * @brief Derive L2 channel key material (Stage 5 SOQ Lightning)
 *
 * @param masterSeed 64-byte BIP-39 derived seed
 * @param channelId Unique channel identifier
 * @param keyType One of: "funding", "revoke", "htlc"
 * @param index Key index (for revocation/HTLC keys)
 * @return 32-byte key material
 */
std::array<uint8_t, 32> DeriveChannelKey(
    const SecureBytes& masterSeed,
    const std::string& channelId,
    const std::string& keyType,
    uint32_t index = 0);

/**
 * @brief Serialize derivation path to bytes for HKDF info
 *
 * @param path Derivation path
 * @return 20-byte encoding (5 × 4-byte components)
 */
std::vector<uint8_t> PathToBytes(const DerivationPath& path);

} // namespace pqwallet
} // namespace soqucoin

#endif // SOQUCOIN_WALLET_PQDERIVE_H
