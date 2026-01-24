// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_WALLET_PQTRANSACTION_H
#define SOQUCOIN_WALLET_PQTRANSACTION_H

/**
 * @file pqtransaction.h
 * @brief Transaction builder with automatic proof aggregation
 *
 * Implements transaction construction that automatically optimizes
 * for per-proof verification costs by aggregating signatures (PAT)
 * and range proofs (BP++) when beneficial.
 */

#include "pqaddress.h"
#include "pqcost.h"
#include "pqkeys.h"
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace soqucoin
{
namespace pqwallet
{

// Forward declarations
class PQAggregator;

/**
 * @brief Transaction output point reference
 */
struct OutPoint {
    std::array<uint8_t, 32> txid;
    uint32_t vout;
    int64_t value; // satoshis
};

/**
 * @brief Transaction output destination
 */
struct TxOutput {
    std::string address;
    int64_t value; // satoshis
};

/**
 * @brief Build result status
 */
enum class BuildResult {
    Success,
    InsufficientFunds,
    InvalidAddress,
    InvalidAmount,
    SigningFailed,
    AggregationFailed
};

/**
 * @brief Completed transaction ready for broadcast
 */
struct PQTransaction {
    std::vector<uint8_t> serialized;
    std::array<uint8_t, 32> txid;
    VerifyCostEstimate verifyCost;
    int64_t fee;
};

/**
 * @brief Transaction builder with automatic aggregation
 *
 * Usage:
 *   auto builder = wallet->CreateTransaction();
 *   builder->AddInput(utxo, keypair);
 *   builder->AddOutput(recipient, amount);
 *   auto result = builder->Build();
 */
class PQTransactionBuilder
{
public:
    PQTransactionBuilder();
    ~PQTransactionBuilder();

    /**
     * @brief Set wallet seed for HKDF-derived blinding factors (GAP-010)
     * @param seed 64-byte wallet master seed
     * @param outputStartIndex Starting output index for blinding derivation
     * @return Reference for chaining
     * @note Required for privacy transaction recovery from seed backup
     */
    PQTransactionBuilder& SetWalletSeed(const std::vector<uint8_t>& seed,
        uint64_t outputStartIndex = 0);

    /**
     * @brief Add input UTXO to spend
     * @param utxo Output point to spend
     * @param key Keypair for signing
     * @return Reference for chaining
     */
    PQTransactionBuilder& AddInput(const OutPoint& utxo,
        const PQKeyPair& key);

    /**
     * @brief Add output destination
     * @param address Recipient address
     * @param value Amount in satoshis
     * @return Reference for chaining
     */
    PQTransactionBuilder& AddOutput(const std::string& address,
        int64_t value);

    /**
     * @brief Set change address
     * @param address Change destination
     * @return Reference for chaining
     */
    PQTransactionBuilder& SetChangeAddress(const std::string& address);

    /**
     * @brief Enable/disable PAT signature aggregation
     * @param enable true to enable (default)
     * @return Reference for chaining
     */
    PQTransactionBuilder& EnablePATAggregation(bool enable = true);

    /**
     * @brief Enable/disable BP++ range proof batching
     * @param enable true to enable (default)
     * @return Reference for chaining
     */
    PQTransactionBuilder& EnableBPPPBatching(bool enable = true);

    /**
     * @brief Set fee rate in satoshis per vbyte
     * @param rate Fee rate
     * @return Reference for chaining
     */
    PQTransactionBuilder& SetFeeRate(int64_t rate);

    /**
     * @brief Estimate verification cost before building
     * @return Cost estimate
     */
    VerifyCostEstimate EstimateVerifyCost() const;

    /**
     * @brief Estimate total fee
     * @return Fee in satoshis
     */
    int64_t EstimateFee() const;

    /**
     * @brief Get savings from aggregation
     * @return Savings information
     */
    AggregationSavings GetAggregationSavings() const;

    /**
     * @brief Build and sign the transaction
     * @return Result status and transaction (nullptr on failure)
     */
    std::pair<BuildResult, std::unique_ptr<PQTransaction> > Build();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace pqwallet
} // namespace soqucoin

#endif // SOQUCOIN_WALLET_PQTRANSACTION_H
