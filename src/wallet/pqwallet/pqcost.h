// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_WALLET_PQCOST_H
#define SOQUCOIN_WALLET_PQCOST_H

/**
 * @file pqcost.h
 * @brief Verification cost estimation for fee calculation
 *
 * Implements per-proof cost accounting as specified in CONSENSUS_COST_SPEC.md.
 * Costs are charged per proof, not per output or per TX.
 */

#include <cstdint>

namespace soqucoin
{
namespace pqwallet
{

/**
 * @brief Verification cost constants from consensus
 */
namespace VerifyCost
{
/// Dilithium signature verification (baseline unit)
constexpr uint32_t DILITHIUM = 1;

/// PAT Merkle proof verification
constexpr uint32_t PAT = 20;

/// Bulletproofs++ range proof verification
constexpr uint32_t BPPP = 50;

/// LatticeFold+ recursive SNARK verification
constexpr uint32_t LATTICEFOLD = 200;

/// Maximum verify cost per block
constexpr uint32_t MAX_BLOCK = 80000;
} // namespace VerifyCost

/**
 * @brief Verification cost breakdown for a transaction
 */
struct VerifyCostEstimate {
    uint32_t dilithiumCost = 0;   ///< Individual signature cost
    uint32_t patCost = 0;         ///< PAT aggregation cost
    uint32_t bpppCost = 0;        ///< Range proof cost
    uint32_t latticeFoldCost = 0; ///< Recursive proof cost

    /// Total verification cost units
    uint32_t Total() const
    {
        return dilithiumCost + patCost + bpppCost + latticeFoldCost;
    }
};

/**
 * @brief Aggregation savings information
 */
struct AggregationSavings {
    uint32_t withoutAggregation; ///< Cost if no aggregation used
    uint32_t withAggregation;    ///< Cost with aggregation

    /// Cost saved by aggregation
    int32_t Savings() const
    {
        return static_cast<int32_t>(withoutAggregation) -
               static_cast<int32_t>(withAggregation);
    }

    /// Savings as percentage
    double SavingsPercent() const
    {
        if (withoutAggregation == 0) return 0.0;
        return 100.0 * Savings() / withoutAggregation;
    }

    /// Is aggregation cost-effective?
    bool IsEffective() const
    {
        return Savings() > 0;
    }
};

/**
 * @brief Fee estimation based on verification costs
 */
class PQFeeEstimator
{
public:
    /**
     * @brief Get recommended fee rate (satoshis per vbyte)
     * @return Current recommended rate
     */
    static int64_t GetRecommendedFeeRate();

    /**
     * @brief Calculate fee from verify cost and TX size
     * @param verifyCost Verification cost estimate
     * @param txSizeBytes Transaction size in bytes
     * @param feeRate Fee rate (satoshis per vbyte)
     * @return Recommended fee in satoshis
     */
    static int64_t CalculateFee(const VerifyCostEstimate& verifyCost,
        size_t txSizeBytes,
        int64_t feeRate);

    /**
     * @brief Check if PAT aggregation is cost-effective
     * @param signatureCount Number of signatures
     * @return true if PAT saves costs
     */
    static bool IsPATCostEffective(uint32_t signatureCount);

    /**
     * @brief Get PAT break-even threshold
     * @return Minimum signatures for PAT benefit
     */
    static uint32_t GetPATThreshold();
};

} // namespace pqwallet
} // namespace soqucoin

#endif // SOQUCOIN_WALLET_PQCOST_H
