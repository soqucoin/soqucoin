// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_WALLET_PQADDRESS_H
#define SOQUCOIN_WALLET_PQADDRESS_H

/**
 * @file pqaddress.h
 * @brief Bech32m address encoding/decoding for post-quantum addresses
 *
 * Implements address format as specified in ADDRESS_FORMAT_SPEC.md:
 * - Mainnet: sq1... / sqp1... / sqsh1...
 * - Testnet: tsq1... / tsqp1... / tsqsh1...
 * - Stagenet: ssq1... / ssqp1... / ssqsh1...
 *
 * Address hash function: BLAKE2b-160 (20 bytes)
 * Why BLAKE2b-160:
 * - 3-5x faster than SHA-256 for large Dilithium keys (1,312 bytes)
 * - 160 bits provides 80-bit collision resistance (sufficient for addresses)
 * - Stronger quantum security margins than SHA-256
 * - Compatible with HKDF for L2 key derivation
 */

#include "pqkeys.h"
#include <array>
#include <optional>
#include <string>

namespace soqucoin
{
namespace pqwallet
{

/**
 * @brief Network type for address encoding
 */
enum class Network {
    Mainnet,
    Testnet,
    Stagenet,
    Unknown
};

/**
 * @brief Address type identifier
 */
enum class AddressType {
    P2PQ,     ///< Pay-to-Post-Quantum (standard Dilithium)
    P2PQ_PAT, ///< P2PQ with PAT aggregation hint
    P2SH_PQ,  ///< Script hash (post-quantum)
    Unknown
};

/**
 * @brief Decoded address information
 */
struct AddressInfo {
    AddressType type = AddressType::Unknown;
    Network network = Network::Unknown;
    std::array<uint8_t, 20> hash{}; ///< BLAKE2b-160 of public key
    bool valid = false;
    std::string error;
};

/**
 * @brief Address encoding/decoding utilities
 */
class PQAddress
{
public:
    /**
     * @brief Encode public key to Bech32m address
     * @param pubkey Dilithium public key
     * @param network Target network
     * @param type Address type (default: P2PQ)
     * @return Bech32m-encoded address string
     */
    static std::string Encode(
        const std::array<uint8_t, DILITHIUM_PUBKEY_SIZE>& pubkey,
        Network network = Network::Mainnet,
        AddressType type = AddressType::P2PQ);

    /**
     * @brief Encode from public key hash
     * @param pubkeyHash 20-byte BLAKE2b-160 hash
     * @param network Target network
     * @param type Address type
     * @return Bech32m-encoded address
     */
    static std::string EncodeFromHash(
        const std::array<uint8_t, 20>& pubkeyHash,
        Network network = Network::Mainnet,
        AddressType type = AddressType::P2PQ);

    /**
     * @brief Decode address string
     * @param address Bech32m address
     * @return AddressInfo with decoded components
     */
    static AddressInfo Decode(const std::string& address);

    /**
     * @brief Validate address format
     * @param address Address string to validate
     * @return true if valid format
     */
    static bool IsValid(const std::string& address);

    /**
     * @brief Detect network from address prefix
     * @param address Address string
     * @return Network type
     */
    static Network DetectNetwork(const std::string& address);

    /**
     * @brief Get human-readable prefix for network
     * @param network Network type
     * @param type Address type
     * @return Prefix string (e.g., "sq1", "tsq1")
     */
    static std::string GetPrefix(Network network, AddressType type);

    /**
     * @brief Compute BLAKE2b-160 hash of public key
     * @param pubkey Dilithium public key
     * @return 20-byte hash (160 bits)
     */
    static std::array<uint8_t, 20> HashPublicKey(
        const std::array<uint8_t, DILITHIUM_PUBKEY_SIZE>& pubkey);
};

} // namespace pqwallet
} // namespace soqucoin

#endif // SOQUCOIN_WALLET_PQADDRESS_H
