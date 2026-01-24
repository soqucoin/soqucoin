// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_WALLET_PQCOINSELECTION_H
#define SOQUCOIN_WALLET_PQCOINSELECTION_H

/**
 * @file pqcoinselection.h
 * @brief Branch-and-Bound coin selection with privacy and L2 awareness
 *
 * Implements intelligent UTXO selection optimized for:
 * - Fee minimization (Branch-and-Bound a la Bitcoin Core)
 * - Privacy preservation (Stage 4 lattice-BP++ compatible)
 * - L2 channel funding (avoid fragmentation)
 * - Stablecoin asset handling (asset-aware selection)
 *
 * ALGORITHMS:
 * 1. Branch-and-Bound (BnB) - Optimal exact match (no change)
 * 2. Single Random Draw (SRD) - Privacy fallback
 * 3. Knapsack - Classic DP approach
 * 4. FIFO - Simple fallback
 *
 * PRIVACY CONSIDERATIONS (Stage 4+):
 * - Avoid linking outputs from different anonymity sets
 * - Prefer spending older UTXOs (decoy aging)
 * - Consolidate during low-fee periods
 *
 * L2 CONSIDERATIONS (Stage 5):
 * - Channel funding prefers single large UTXO (2-of-2 multisig)
 * - Avoid dust outputs that can't pay channel fees
 * - Reserve selection for anchor outputs
 *
 * References:
 * - BIP-125 (Replace-by-Fee)
 * - Bitcoin Core coin selection (src/wallet/coinselection.cpp)
 * - Murch's ergo-pinning-fee paper
 */

#include "wallet/pqwallet/pqfee.h"
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace soqucoin
{
namespace pqwallet
{

/**
 * @brief Represents a spendable UTXO
 */
struct CoinOutput {
    std::string txid;       ///< Transaction ID
    uint32_t vout;          ///< Output index
    int64_t value;          ///< Value in satoshis
    uint32_t confirmations; ///< Confirmation depth
    int64_t effectiveValue; ///< Value minus fee to spend

    // Privacy metadata (Stage 4+)
    uint32_t anonSetId;   ///< Anonymity set identifier
    uint64_t blockHeight; ///< Block height when created
    bool isPrivate;       ///< Uses BP++ range proofs

    // Asset metadata (Stage 3+)
    std::string assetId; ///< Asset ID (empty = SOQ native)
    bool isAsset() const { return !assetId.empty(); }

    // Comparison for sets
    bool operator<(const CoinOutput& other) const
    {
        return txid < other.txid || (txid == other.txid && vout < other.vout);
    }

    bool operator==(const CoinOutput& other) const
    {
        return txid == other.txid && vout == other.vout;
    }
};

/**
 * @brief Coin selection algorithm choice
 */
enum class SelectionAlgorithm {
    AUTOMATIC,        ///< Let selector choose optimal algorithm
    BRANCH_AND_BOUND, ///< Exact match (no change)
    SINGLE_RANDOM,    ///< Privacy-preserving random selection
    KNAPSACK,         ///< Dynamic programming approach
    FIFO,             ///< First-in-first-out (oldest first)
    LARGEST_FIRST     ///< Largest UTXOs first (minimizes inputs)
};

/**
 * @brief Selection mode for different use cases
 */
enum class SelectionMode {
    NORMAL,          ///< Standard payment
    CHANNEL_FUNDING, ///< L2 Lightning channel open
    PRIVACY_OPTIMAL, ///< Maximum privacy (Stage 4)
    FEE_OPTIMAL,     ///< Minimum fees
    CONSOLIDATE      ///< Reduce UTXO count
};

/**
 * @brief Result of coin selection
 */
struct SelectionResult {
    bool success;                     ///< Selection succeeded
    std::vector<CoinOutput> selected; ///< Selected UTXOs
    int64_t selectedTotal;            ///< Sum of selected values
    int64_t targetAmount;             ///< Target amount
    int64_t fee;                      ///< Estimated fee
    int64_t change;                   ///< Change amount (0 if exact)
    SelectionAlgorithm algorithmUsed; ///< Which algorithm succeeded

    /// Waste metric (lower is better)
    int64_t GetWaste() const
    {
        // Waste = excess + cost of change output creation
        constexpr int64_t CHANGE_COST = 34 * 10; // ~34 vB at 10 sat/vB
        return (change > 0 ? CHANGE_COST : 0) + (selectedTotal - targetAmount - fee);
    }

    /// Number of inputs selected
    size_t InputCount() const { return selected.size(); }

    /// Is this an exact match (no change)?
    bool IsExactMatch() const { return change == 0; }
};

/**
 * @brief Coin selection options
 */
struct SelectionOptions {
    SelectionAlgorithm algorithm = SelectionAlgorithm::AUTOMATIC;
    SelectionMode mode = SelectionMode::NORMAL;

    // Fee parameters
    FeeRate feeRate = 10000;        ///< sat/vB (default 10)
    FeeRate longTermFeeRate = 5000; ///< For waste calculation

    // Constraints
    int64_t minChange = 1000;      ///< Minimum change output
    int64_t dustThreshold = 546;   ///< Dust limit
    uint32_t maxInputs = 500;      ///< Maximum inputs per TX
    uint32_t minConfirmations = 1; ///< Minimum UTXO confirmations

    // Privacy options (Stage 4+)
    bool preferPrivateOutputs = false; ///< Prefer BP++ outputs
    bool avoidMixingAnonSets = true;   ///< Don't mix anonymity sets

    // L2 options (Stage 5)
    bool channelFundingMode = false; ///< Prefer single large UTXO
    int64_t channelReserve = 0;      ///< Additional reserve needed

    // Asset options (Stage 3)
    std::string selectAssetId; ///< Only select this asset (empty = SOQ)
};

/**
 * @brief Branch-and-Bound coin selector
 */
class PQCoinSelector
{
public:
    /**
     * @brief Select coins for a target amount
     * @param availableCoins All spendable UTXOs
     * @param targetAmount Target value (satoshis)
     * @param options Selection options
     * @return Selection result
     */
    static SelectionResult SelectCoins(
        const std::vector<CoinOutput>& availableCoins,
        int64_t targetAmount,
        const SelectionOptions& options = SelectionOptions());

    /**
     * @brief Select coins for L2 channel funding
     * Optimized for 2-of-2 multisig funding TX
     * @param availableCoins Available UTXOs
     * @param channelCapacity Desired channel capacity
     * @param reserve Channel reserve requirement
     * @return Selection result
     */
    static SelectionResult SelectForChannel(
        const std::vector<CoinOutput>& availableCoins,
        int64_t channelCapacity,
        int64_t reserve = 0);

    /**
     * @brief Select coins with privacy optimization
     * For Stage 4 lattice-BP++ transactions
     * @param availableCoins Available UTXOs
     * @param targetAmount Target value
     * @return Selection result with privacy considerations
     */
    static SelectionResult SelectPrivate(
        const std::vector<CoinOutput>& availableCoins,
        int64_t targetAmount);

    /**
     * @brief Select coins for consolidation
     * Reduce UTXO count during low-fee periods
     * @param availableCoins Available UTXOs
     * @param maxFeeRate Maximum fee rate to pay
     * @return Selection result for consolidation
     */
    static SelectionResult SelectForConsolidation(
        const std::vector<CoinOutput>& availableCoins,
        FeeRate maxFeeRate);

private:
    //=========================================================================
    // Algorithm implementations
    //=========================================================================

    /**
     * @brief Branch-and-Bound exact match
     * Tries to find exact match (no change output)
     */
    static std::optional<SelectionResult> BranchAndBound(
        std::vector<CoinOutput>& coins,
        int64_t targetValue,
        int64_t costOfChange,
        size_t maxIterations = 100000);

    /**
     * @brief Single Random Draw
     * Privacy-preserving random selection
     */
    static SelectionResult SingleRandomDraw(
        const std::vector<CoinOutput>& coins,
        int64_t targetValue);

    /**
     * @brief Knapsack dynamic programming
     * Classic DP approach for near-optimal selection
     */
    static SelectionResult Knapsack(
        const std::vector<CoinOutput>& coins,
        int64_t targetValue);

    /**
     * @brief FIFO selection
     * Simple oldest-first selection
     */
    static SelectionResult FIFO(
        std::vector<CoinOutput> coins,
        int64_t targetValue);

    /**
     * @brief Largest-first selection
     * Minimize input count
     */
    static SelectionResult LargestFirst(
        std::vector<CoinOutput> coins,
        int64_t targetValue);

    //=========================================================================
    // Utility functions
    //=========================================================================

    /// Calculate effective value (value - fee to spend)
    static int64_t CalculateEffectiveValue(
        const CoinOutput& coin,
        FeeRate feeRate);

    /// Filter coins by criteria
    static std::vector<CoinOutput> FilterCoins(
        const std::vector<CoinOutput>& coins,
        const SelectionOptions& options);

    /// Check if selection meets privacy requirements
    static bool MeetsPrivacyRequirements(
        const std::vector<CoinOutput>& selected,
        const SelectionOptions& options);
};

} // namespace pqwallet
} // namespace soqucoin

#endif // SOQUCOIN_WALLET_PQCOINSELECTION_H
