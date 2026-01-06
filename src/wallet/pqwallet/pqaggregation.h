// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_WALLET_PQAGGREGATION_H
#define SOQUCOIN_WALLET_PQAGGREGATION_H

/**
 * @file pqaggregation.h
 * @brief Proof aggregation utilities (PAT and BP++ batching)
 *
 * Implements automatic proof aggregation to minimize per-proof costs:
 * - PAT: Aggregates multiple Dilithium signatures into single Merkle proof
 * - BP++: Batches multiple range proofs into single aggregated proof
 */

#include "pqkeys.h"
#include <array>
#include <memory>
#include <vector>

namespace soqucoin
{
namespace pqwallet
{

/**
 * @brief PAT proof data
 */
struct PATProof {
    std::vector<uint8_t> proof;
    uint32_t signatureCount;

    /// Verification cost (always 20 units regardless of sig count)
    static constexpr uint32_t VERIFY_COST = 20;
};

/**
 * @brief Aggregated BP++ range proof
 */
struct BPPPRangeProof {
    std::vector<uint8_t> proof;
    uint32_t outputCount;

    /// Verification cost (always 50 units regardless of output count)
    static constexpr uint32_t VERIFY_COST = 50;
};

/**
 * @brief PAT signature aggregation builder
 *
 * Aggregates multiple Dilithium signatures into a single Merkle proof.
 * Cost-effective when signature count >= 20.
 */
class PATBuilder
{
public:
    PATBuilder();
    ~PATBuilder();

    /**
     * @brief Add signature to aggregation batch
     * @param signature Dilithium signature
     * @param pubkey Corresponding public key
     * @param message Signed message
     */
    void AddSignature(
        const std::array<uint8_t, DILITHIUM_SIGNATURE_SIZE>& signature,
        const std::array<uint8_t, DILITHIUM_PUBKEY_SIZE>& pubkey,
        const std::vector<uint8_t>& message);

    /**
     * @brief Get current signature count
     */
    uint32_t GetSignatureCount() const;

    /**
     * @brief Check if aggregation is cost-effective
     * @return true if signatures >= threshold (20)
     */
    bool IsCostEffective() const;

    /**
     * @brief Get cost comparison
     */
    struct CostComparison {
        uint32_t withoutPAT; ///< Cost without aggregation
        uint32_t withPAT;    ///< Cost with PAT
        int32_t savings;     ///< Savings (can be negative for small batches)
    };
    CostComparison GetCostComparison() const;

    /**
     * @brief Build aggregated PAT proof
     * @return PAT proof or nullopt if building fails
     */
    std::optional<PATProof> Build();

    /**
     * @brief Clear all signatures and reset builder
     */
    void Reset();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

/**
 * @brief BP++ range proof batching builder
 */
class BPPPBatcher
{
public:
    BPPPBatcher();
    ~BPPPBatcher();

    /**
     * @brief Add value to batch for range proof
     * @param value Value to prove (must be positive)
     */
    void AddValue(int64_t value);

    /**
     * @brief Get current output count
     */
    uint32_t GetOutputCount() const;

    /**
     * @brief Estimate verification cost
     * @return Always 50 units per proof
     */
    uint32_t EstimateCost() const;

    /**
     * @brief Build batched range proof
     * @return Range proof or nullopt if building fails
     */
    std::optional<BPPPRangeProof> Build();

    /**
     * @brief Clear all values and reset builder
     */
    void Reset();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace pqwallet
} // namespace soqucoin

#endif // SOQUCOIN_WALLET_PQAGGREGATION_H
