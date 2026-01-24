// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_WALLET_PQFEE_H
#define SOQUCOIN_WALLET_PQFEE_H

/**
 * @file pqfee.h
 * @brief Block-aware, L2-ready fee estimation for Soqucoin
 *
 * Implements intelligent fee estimation with support for:
 * - Block-aware mempool analysis (Bitcoin Core style)
 * - Per-proof cost accounting (Soqucoin-specific)
 * - L2 Lightning channel operations (reserve, HTLC, force-close)
 * - Stablecoin asset transactions
 *
 * L2 COMPATIBILITY:
 * - Channel reserve calculations per BOLT-2
 * - HTLC timeout/success fee estimates
 * - Emergency force-close fee buffers
 * - Anchor output support (future)
 */

#include "wallet/pqwallet/pqcost.h"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace soqucoin
{
namespace pqwallet
{

/// Fee rate units (satoshis per virtual byte)
using FeeRate = int64_t;

/// Confirmation target (blocks)
using ConfTarget = uint32_t;

/// Channel capacity (satoshis)
using ChannelCapacity = int64_t;

/**
 * @brief Fee estimation modes
 */
enum class FeeEstimateMode {
    UNSET,       ///< Use default estimation
    ECONOMICAL,  ///< Minimize fees, slower confirmation
    CONSERVATIVE ///< Ensure inclusion, higher fees
};

/**
 * @brief L2 Lightning operation types for fee calculation
 */
enum class L2OperationType {
    CHANNEL_OPEN,        ///< 2-of-2 multisig funding TX
    CHANNEL_CLOSE_COOP,  ///< Cooperative close
    CHANNEL_CLOSE_FORCE, ///< Unilateral close (needs buffer)
    HTLC_SUCCESS,        ///< HTLC claim with preimage
    HTLC_TIMEOUT,        ///< HTLC timeout refund
    ANCHOR_CPFP,         ///< Child-pays-for-parent anchor (future)
    SPLICE_IN,           ///< Channel splice-in (future)
    SPLICE_OUT           ///< Channel splice-out (future)
};

/**
 * @brief Fee estimate result with confidence metrics
 */
struct FeeEstimateResult {
    FeeRate feeRate;       ///< Recommended fee rate (sat/vB)
    ConfTarget confTarget; ///< Expected confirmation blocks
    double confidence;     ///< Confidence level (0.0 - 1.0)
    int64_t absoluteFee;   ///< Absolute fee for estimated TX size

    /// Human-readable description
    std::string GetDescription() const;
};

/**
 * @brief L2 channel reserve requirements
 */
struct ChannelReserve {
    int64_t localReserve;    ///< Our committed reserve (can't spend)
    int64_t remoteReserve;   ///< Peer's required reserve
    int64_t dustLimit;       ///< Minimum output value
    int64_t htlcMinimum;     ///< Minimum HTLC amount
    int64_t maxHtlcInFlight; ///< Maximum pending HTLC value

    /// Calculate usable channel capacity after reserves
    int64_t UsableCapacity(ChannelCapacity totalCapacity) const
    {
        return totalCapacity - localReserve - remoteReserve;
    }
};

/**
 * @brief Block-aware, L2-ready fee estimator
 */
class PQFeeEstimator2
{
public:
    //=========================================================================
    // Singleton access (shares state across wallet)
    //=========================================================================

    static PQFeeEstimator2& GetInstance();

    //=========================================================================
    // Basic fee estimation (L1 transactions)
    //=========================================================================

    /**
     * @brief Estimate fee for confirmation target
     * @param confTarget Desired confirmation blocks (1-1008)
     * @param mode Estimation strategy
     * @param txSize Optional TX size for absolute fee
     * @return Fee estimate result
     */
    FeeEstimateResult EstimateFee(
        ConfTarget confTarget,
        FeeEstimateMode mode = FeeEstimateMode::CONSERVATIVE,
        size_t txSize = 0) const;

    /**
     * @brief Get minimum relay fee
     * @return Minimum fee rate accepted by network
     */
    FeeRate GetMinRelayFee() const;

    /**
     * @brief Get urgency-based smart fee
     * Priority: Urgent (1-2 blocks), Normal (3-6), Economy (6-12)
     */
    FeeEstimateResult GetSmartFee(const std::string& priority = "normal") const;

    //=========================================================================
    // Per-proof cost integration (Soqucoin-specific)
    //=========================================================================

    /**
     * @brief Calculate fee including verification costs
     * @param verifyCost Verification cost breakdown
     * @param txSizeBytes Transaction size
     * @param confTarget Confirmation target
     * @return Combined fee (size + verify cost components)
     */
    int64_t CalculateFeeWithVerifyCost(
        const VerifyCostEstimate& verifyCost,
        size_t txSizeBytes,
        ConfTarget confTarget = 6) const;

    //=========================================================================
    // L2 Lightning channel operations
    //=========================================================================

    /**
     * @brief Estimate fee for L2 operation
     * @param opType Type of Lightning operation
     * @param capacity Channel capacity (for reserve calcs)
     * @return Fee estimate with appropriate buffer
     */
    FeeEstimateResult EstimateL2Fee(
        L2OperationType opType,
        ChannelCapacity capacity = 0) const;

    /**
     * @brief Calculate channel reserves per BOLT-2
     * @param capacity Total channel capacity
     * @param isInitiator Are we the channel opener?
     * @return Reserve requirements
     */
    ChannelReserve CalculateChannelReserve(
        ChannelCapacity capacity,
        bool isInitiator = true) const;

    /**
     * @brief Get force-close fee buffer
     * @return Emergency fee (10x normal for time-sensitive closes)
     */
    int64_t GetForceCloseBuffer() const;

    /**
     * @brief Check if capacity meets minimum channel requirements
     * @param capacity Proposed channel size
     * @return true if viable, false if too small
     */
    bool IsViableChannelCapacity(ChannelCapacity capacity) const;

    //=========================================================================
    // Stablecoin/asset support (Stage 3 ready)
    //=========================================================================

    /**
     * @brief Estimate fee for asset transfer
     * Asset TXs may have metadata overhead
     * @param assetId Asset identifier
     * @param txSizeBytes Estimated TX size
     * @return Fee estimate
     */
    FeeEstimateResult EstimateAssetFee(
        const std::string& assetId,
        size_t txSizeBytes) const;

    //=========================================================================
    // Mempool tracking (block awareness)
    //=========================================================================

    /**
     * @brief Update fee estimates from mempool state
     * Called when new block arrives or mempool changes significantly
     */
    void UpdateFromMempool();

    /**
     * @brief Get current mempool congestion level
     * @return 0.0 (empty) to 1.0 (full)
     */
    double GetMempoolCongestion() const;

    /**
     * @brief Get fee percentiles from recent blocks
     * @param numBlocks Number of blocks to analyze (1-100)
     * @return Fee rates at 10th, 50th, 90th percentile
     */
    struct FeePercentiles {
        FeeRate p10; ///< 10th percentile (economy)
        FeeRate p50; ///< Median fee rate
        FeeRate p90; ///< 90th percentile (priority)
    };
    FeePercentiles GetRecentFeePercentiles(uint32_t numBlocks = 6) const;

private:
    PQFeeEstimator2() = default;

    // Cached state
    mutable FeeRate m_cachedMinFee{1000}; // 1 sat/vB default
    mutable double m_congestion{0.0};
    mutable uint64_t m_lastUpdate{0};

    // Constants
    static constexpr FeeRate MIN_RELAY_FEE = 1000;         // 1 sat/vB
    static constexpr FeeRate DUST_RELAY_FEE = 3000;        // 3 sat/vB
    static constexpr int64_t MIN_CHANNEL_CAPACITY = 20000; // 20k sats
    static constexpr double RESERVE_PERCENT = 0.01;        // 1% per BOLT-2
};

} // namespace pqwallet
} // namespace soqucoin

#endif // SOQUCOIN_WALLET_PQFEE_H
