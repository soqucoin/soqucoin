// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_WALLET_PQWALLET_H
#define SOQUCOIN_WALLET_PQWALLET_H

/**
 * @file pqwallet.h
 * @brief Main post-quantum wallet interface for Soqucoin
 *
 * This is the primary entry point for post-quantum wallet operations.
 * It coordinates Dilithium key management, address generation,
 * transaction construction, and proof aggregation.
 *
 * @note Implementation pending. This header defines the public API surface
 *       for audit scoping purposes.
 *
 * @see doc/WALLET_API_SPEC.md for detailed API documentation
 * @see doc/ADDRESS_FORMAT_SPEC.md for address encoding details
 * @see doc/WALLET_TEST_VECTORS.md for implementation test vectors
 */

#include "pqaddress.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace soqucoin
{
namespace pqwallet
{

// Forward declarations
class PQKeyPair;
class PQAddress;
class PQTransactionBuilder;
class PQFeeEstimator;

/**
 * @brief Configuration for aggregation behavior
 */
struct AggregationConfig {
    uint32_t patThreshold = 20;     ///< Min signatures for PAT benefit
    bool autoAggregate = true;      ///< Auto-detect when to aggregate
    bool enableBPPPBatching = true; ///< Enable BP++ output batching
};

/**
 * @brief Main post-quantum wallet class
 *
 * The PQWallet class provides:
 * - Dilithium keypair creation and management
 * - Bech32m address generation (sq1/tsq1/ssq1)
 * - Transaction construction with automatic aggregation
 * - Fee estimation based on per-proof verification costs
 *
 * Design follows expert blockchain wallet best practices:
 * - Secure by default (keys never exposed)
 * - Aggregation by default (PAT/BP++ auto-enabled)
 * - Hardware wallet compatible (signing interface abstracted)
 */
class PQWallet
{
public:
    /**
     * @brief Create new wallet from 64-byte seed
     * @param seed BIP-39 derived seed
     * @param network Target network (default: Testnet)
     * @return Wallet instance or nullptr on error
     */
    static std::unique_ptr<PQWallet> FromSeed(const std::vector<uint8_t>& seed,
        Network network = Network::Testnet);

    /**
     * @brief Create watch-only wallet from extended public key
     * @param masterPubKey Master public key (1312 bytes Dilithium)
     * @param network Target network
     * @return Watch-only wallet instance
     * @note Watch-only wallets cannot sign transactions
     */
    static std::unique_ptr<PQWallet> FromPublicKey(
        const std::vector<uint8_t>& masterPubKey,
        Network network = Network::Testnet);

    /**
     * @brief Create watch-only wallet from list of addresses
     * @param addresses Addresses to watch (sq1.../tsq1...)
     * @return Watch-only wallet instance
     */
    static std::unique_ptr<PQWallet> WatchOnly(
        const std::vector<std::string>& addresses);

    /**
     * @brief Load wallet from encrypted file
     * @param path Path to wallet file
     * @param passphrase Decryption passphrase
     * @return Wallet instance or nullptr on error
     */
    static std::unique_ptr<PQWallet> Load(const std::string& path,
        const std::string& passphrase);

    /**
     * @brief Save wallet to encrypted file
     * @param path Destination path
     * @param passphrase Encryption passphrase
     * @return true on success
     */
    bool Save(const std::string& path, const std::string& passphrase) const;

    //=========================================================================
    // Watch-Only Mode
    //=========================================================================

    /**
     * @brief Check if wallet is in watch-only mode
     * @return true if no secret keys are available
     */
    bool IsWatchOnly() const;

    /**
     * @brief Import address for watch-only tracking
     * @param address Bech32m address to watch
     * @param label Optional descriptive label
     * @return true on success
     */
    bool ImportWatchOnlyAddress(const std::string& address,
        const std::string& label = "");

    /**
     * @brief Import extended public key for watch-only HD derivation
     * @param extPubKey Extended public key (xpub equivalent for Dilithium)
     * @param label Optional descriptive label
     * @return true on success
     */
    bool ImportExtendedPublicKey(const std::vector<uint8_t>& extPubKey,
        const std::string& label = "");

    /**
     * @brief Get list of watched addresses
     * @return Vector of (address, label) pairs
     */
    std::vector<std::pair<std::string, std::string> > GetWatchedAddresses() const;

    //=========================================================================
    // Address Generation
    //=========================================================================

    /**
     * @brief Generate new receiving address
     * @return Bech32m address (sq1... mainnet, tsq1... testnet)
     */
    std::string GetNewAddress();

    /**
     * @brief Get address at specific BIP-44 path
     * @param account Account index (m/44'/21329'/account'/...)
     * @param change 0 for external, 1 for change
     * @param index Address index
     * @return Bech32m address
     */
    std::string GetAddress(uint32_t account, uint32_t change, uint32_t index);

    //=========================================================================
    // Transaction Building
    //=========================================================================

    /**
     * @brief Create transaction builder for this wallet
     * @return Builder with current aggregation config
     * @throws runtime_error if wallet is watch-only
     */
    std::unique_ptr<PQTransactionBuilder> CreateTransaction();

    /**
     * @brief Get current aggregation configuration
     */
    const AggregationConfig& GetAggregationConfig() const;

    /**
     * @brief Update aggregation configuration
     */
    void SetAggregationConfig(const AggregationConfig& config);

    virtual ~PQWallet();

    // Constructor is public to enable make_unique
    PQWallet();

private:
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace pqwallet
} // namespace soqucoin

#endif // SOQUCOIN_WALLET_PQWALLET_H
