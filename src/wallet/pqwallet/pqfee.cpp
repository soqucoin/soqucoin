// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/pqwallet/pqfee.h"
#include <algorithm>
#include <cmath>
#include <ctime>

namespace soqucoin
{
namespace pqwallet
{

//=============================================================================
// Singleton instance
//=============================================================================

PQFeeEstimator2& PQFeeEstimator2::GetInstance()
{
    static PQFeeEstimator2 instance;
    return instance;
}

//=============================================================================
// Basic L1 fee estimation
//=============================================================================

FeeEstimateResult PQFeeEstimator2::EstimateFee(
    ConfTarget confTarget,
    FeeEstimateMode mode,
    size_t txSize) const
{
    FeeEstimateResult result;
    result.confTarget = std::clamp(confTarget, 1u, 1008u);

    // Base rate lookup by confirmation target
    // These are conservative defaults - real implementation would query mempool
    FeeRate baseRate;
    if (confTarget <= 2) {
        baseRate = 20000; // 20 sat/vB for next-block
    } else if (confTarget <= 6) {
        baseRate = 10000; // 10 sat/vB for ~1 hour
    } else if (confTarget <= 12) {
        baseRate = 5000; // 5 sat/vB for ~2 hours
    } else if (confTarget <= 48) {
        baseRate = 2000; // 2 sat/vB for ~8 hours
    } else {
        baseRate = 1000; // 1 sat/vB for economical
    }

    // Apply mode adjustment
    switch (mode) {
    case FeeEstimateMode::ECONOMICAL:
        baseRate = std::max(MIN_RELAY_FEE, baseRate * 80 / 100);
        result.confidence = 0.7;
        break;
    case FeeEstimateMode::CONSERVATIVE:
        baseRate = baseRate * 120 / 100;
        result.confidence = 0.95;
        break;
    default:
        result.confidence = 0.85;
        break;
    }

    // Apply congestion multiplier
    if (m_congestion > 0.8) {
        baseRate = baseRate * 150 / 100; // +50% when congested
    } else if (m_congestion > 0.5) {
        baseRate = baseRate * 120 / 100; // +20% when moderately busy
    }

    result.feeRate = baseRate;
    result.absoluteFee = txSize > 0 ? (baseRate * static_cast<int64_t>(txSize)) / 1000 : 0;

    return result;
}

FeeRate PQFeeEstimator2::GetMinRelayFee() const
{
    return MIN_RELAY_FEE;
}

FeeEstimateResult PQFeeEstimator2::GetSmartFee(const std::string& priority) const
{
    ConfTarget target;
    FeeEstimateMode mode;

    if (priority == "urgent" || priority == "high") {
        target = 2;
        mode = FeeEstimateMode::CONSERVATIVE;
    } else if (priority == "economy" || priority == "low") {
        target = 12;
        mode = FeeEstimateMode::ECONOMICAL;
    } else {
        // Normal/default
        target = 6;
        mode = FeeEstimateMode::UNSET;
    }

    return EstimateFee(target, mode);
}

//=============================================================================
// Per-proof cost integration (Soqucoin-specific)
//=============================================================================

int64_t PQFeeEstimator2::CalculateFeeWithVerifyCost(
    const VerifyCostEstimate& verifyCost,
    size_t txSizeBytes,
    ConfTarget confTarget) const
{
    auto estimate = EstimateFee(confTarget, FeeEstimateMode::CONSERVATIVE, txSizeBytes);

    // Add verification cost component
    // Verify cost units are priced at 10 satoshis per unit (configurable)
    constexpr int64_t SATOSHI_PER_VERIFY_UNIT = 10;

    int64_t sizeFee = estimate.absoluteFee;
    int64_t verifyCostFee = verifyCost.Total() * SATOSHI_PER_VERIFY_UNIT;

    return sizeFee + verifyCostFee;
}

//=============================================================================
// L2 Lightning channel operations
//=============================================================================

FeeEstimateResult PQFeeEstimator2::EstimateL2Fee(
    L2OperationType opType,
    ChannelCapacity capacity) const
{
    FeeEstimateResult result;

    // Estimated TX sizes for different L2 operations (vbytes)
    size_t txSize;
    ConfTarget target;
    FeeEstimateMode mode = FeeEstimateMode::CONSERVATIVE;

    switch (opType) {
    case L2OperationType::CHANNEL_OPEN:
        // 2-of-2 multisig funding: ~250 vB (Dilithium larger)
        txSize = 2800; // PQ signatures are ~2.4KB each
        target = 6;
        break;

    case L2OperationType::CHANNEL_CLOSE_COOP:
        // Cooperative close: ~300 vB (2 outputs, 2 sigs)
        txSize = 3200;
        target = 12; // Can wait a bit
        mode = FeeEstimateMode::ECONOMICAL;
        break;

    case L2OperationType::CHANNEL_CLOSE_FORCE:
        // Force close: URGENT - safety-critical
        txSize = 4000; // Commitment TX with scripts
        target = 1;
        // Add buffer for fee bumping
        break;

    case L2OperationType::HTLC_SUCCESS:
        // HTLC success: preimage reveal
        txSize = 3500;
        target = 3; // Time-sensitive
        break;

    case L2OperationType::HTLC_TIMEOUT:
        // HTLC timeout: after expiry
        txSize = 3500;
        target = 6;
        break;

    case L2OperationType::ANCHOR_CPFP:
        // Anchor output CPFP: small
        txSize = 200;
        target = 1;
        break;

    case L2OperationType::SPLICE_IN:
    case L2OperationType::SPLICE_OUT:
        txSize = 4000;
        target = 6;
        break;

    default:
        txSize = 3000;
        target = 6;
    }

    result = EstimateFee(target, mode, txSize);

    // Force close needs emergency buffer (10x safety margin)
    if (opType == L2OperationType::CHANNEL_CLOSE_FORCE) {
        result.feeRate *= 10;
        result.absoluteFee *= 10;
        result.confidence = 0.99; // Must confirm
    }

    return result;
}

ChannelReserve PQFeeEstimator2::CalculateChannelReserve(
    ChannelCapacity capacity,
    bool isInitiator) const
{
    ChannelReserve reserve;

    // BOLT-2: reserve should be >= 1% of channel capacity
    int64_t baseReserve = static_cast<int64_t>(capacity * RESERVE_PERCENT);

    // But also at least dust limit
    reserve.localReserve = std::max(baseReserve, int64_t{546});
    reserve.remoteReserve = std::max(baseReserve, int64_t{546});

    // Initiator pays fees, so needs larger reserve
    if (isInitiator) {
        // Reserve enough for worst-case force close
        int64_t forceCloseFee = GetForceCloseBuffer();
        reserve.localReserve = std::max(reserve.localReserve, forceCloseFee);
    }

    // Dust limit: 546 sats for standard outputs
    reserve.dustLimit = 546;

    // HTLC minimum: above dust to prevent dust attacks
    reserve.htlcMinimum = 1000; // 1000 sats

    // Max HTLC in flight: 90% of capacity (leave room for fees)
    reserve.maxHtlcInFlight = capacity * 90 / 100;

    return reserve;
}

int64_t PQFeeEstimator2::GetForceCloseBuffer() const
{
    // Estimate force close cost at 10x normal priority
    auto urgentEstimate = EstimateFee(1, FeeEstimateMode::CONSERVATIVE, 4000);
    return urgentEstimate.absoluteFee * 10;
}

bool PQFeeEstimator2::IsViableChannelCapacity(ChannelCapacity capacity) const
{
    // Minimum viable channel: reserves + fees + usable amount
    auto reserve = CalculateChannelReserve(capacity, true);
    int64_t forceCloseFee = GetForceCloseBuffer();

    // Need at least 10000 sats usable after reserves and fees
    int64_t usable = reserve.UsableCapacity(capacity) - forceCloseFee;
    return usable >= 10000;
}

//=============================================================================
// Stablecoin/asset support
//=============================================================================

FeeEstimateResult PQFeeEstimator2::EstimateAssetFee(
    const std::string& assetId,
    size_t txSizeBytes) const
{
    // Asset transactions have ~100 bytes overhead for asset metadata
    size_t adjustedSize = txSizeBytes + 100;

    // Use normal priority for asset transfers
    return EstimateFee(6, FeeEstimateMode::CONSERVATIVE, adjustedSize);
}

//=============================================================================
// Mempool tracking
//=============================================================================

void PQFeeEstimator2::UpdateFromMempool()
{
    // In production: query mempool for actual fee distribution
    // For now: use time-based simulation

    uint64_t now = static_cast<uint64_t>(std::time(nullptr));

    // Update at most once per 10 seconds
    if (now - m_lastUpdate < 10) {
        return;
    }
    m_lastUpdate = now;

    // Simulate congestion based on time of day (placeholder)
    // Real implementation would query getmempoolinfo
    int hour = (now / 3600) % 24;

    // Higher congestion during business hours (simulated)
    if (hour >= 9 && hour <= 17) {
        m_congestion = 0.6 + (std::sin(hour * 0.5) * 0.2);
    } else {
        m_congestion = 0.3;
    }
}

double PQFeeEstimator2::GetMempoolCongestion() const
{
    return m_congestion;
}

PQFeeEstimator2::FeePercentiles PQFeeEstimator2::GetRecentFeePercentiles(
    uint32_t numBlocks) const
{
    // In production: analyze recent blocks for actual fee distribution
    // For now: return estimates based on current congestion

    FeePercentiles result;

    FeeRate baseRate = 5000; // 5 sat/vB baseline

    // Adjust by congestion
    baseRate = static_cast<FeeRate>(baseRate * (1.0 + m_congestion));

    result.p10 = baseRate * 50 / 100;  // Economy: 50% of median
    result.p50 = baseRate;             // Median
    result.p90 = baseRate * 200 / 100; // Priority: 200% of median

    return result;
}

//=============================================================================
// Result formatting
//=============================================================================

std::string FeeEstimateResult::GetDescription() const
{
    std::string desc = "Fee: " + std::to_string(feeRate / 1000) + " sat/vB";
    desc += ", Target: " + std::to_string(confTarget) + " blocks";
    desc += ", Confidence: " + std::to_string(static_cast<int>(confidence * 100)) + "%";
    if (absoluteFee > 0) {
        desc += ", Total: " + std::to_string(absoluteFee) + " sats";
    }
    return desc;
}

} // namespace pqwallet
} // namespace soqucoin
