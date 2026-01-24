// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/pqwallet/pqcoinselection.h"
#include <algorithm>
#include <limits>
#include <numeric>
#include <random>

namespace soqucoin
{
namespace pqwallet
{

//=============================================================================
// Public API
//=============================================================================

SelectionResult PQCoinSelector::SelectCoins(
    const std::vector<CoinOutput>& availableCoins,
    int64_t targetAmount,
    const SelectionOptions& options)
{
    // Filter coins first
    auto eligibleCoins = FilterCoins(availableCoins, options);

    if (eligibleCoins.empty()) {
        return SelectionResult{false, {}, 0, targetAmount, 0, 0, SelectionAlgorithm::AUTOMATIC};
    }

    // Calculate effective values (value - cost to spend)
    for (auto& coin : eligibleCoins) {
        coin.effectiveValue = CalculateEffectiveValue(coin, options.feeRate);
    }

    // Remove negative effective value coins
    eligibleCoins.erase(
        std::remove_if(eligibleCoins.begin(), eligibleCoins.end(),
            [](const CoinOutput& c) { return c.effectiveValue <= 0; }),
        eligibleCoins.end());

    if (eligibleCoins.empty()) {
        return SelectionResult{false, {}, 0, targetAmount, 0, 0, SelectionAlgorithm::AUTOMATIC};
    }

    // Calculate total available
    int64_t totalAvailable = std::accumulate(eligibleCoins.begin(), eligibleCoins.end(), int64_t{0},
        [](int64_t sum, const CoinOutput& c) { return sum + c.effectiveValue; });

    if (totalAvailable < targetAmount) {
        return SelectionResult{false, {}, 0, targetAmount, 0, 0, SelectionAlgorithm::AUTOMATIC};
    }

    // Choose algorithm based on options
    SelectionAlgorithm algo = options.algorithm;

    if (algo == SelectionAlgorithm::AUTOMATIC) {
        // Automatic selection strategy:
        // 1. Try BnB for exact match (best for fees)
        // 2. If channel funding mode, try largest first
        // 3. Fall back to knapsack
        // 4. Last resort: FIFO

        if (options.mode == SelectionMode::CHANNEL_FUNDING) {
            return LargestFirst(eligibleCoins, targetAmount);
        }

        if (options.mode == SelectionMode::PRIVACY_OPTIMAL) {
            return SingleRandomDraw(eligibleCoins, targetAmount);
        }

        // Calculate cost of change for BnB
        int64_t costOfChange = (34 + 68) * options.feeRate / 1000; // ~102 vB for change

        auto bnbResult = BranchAndBound(eligibleCoins, targetAmount, costOfChange);
        if (bnbResult && bnbResult->success) {
            return *bnbResult;
        }

        // Fall back to knapsack
        auto knapsackResult = Knapsack(eligibleCoins, targetAmount);
        if (knapsackResult.success) {
            return knapsackResult;
        }

        // Last resort: FIFO
        return FIFO(eligibleCoins, targetAmount);
    }

    // Explicit algorithm selection
    switch (algo) {
    case SelectionAlgorithm::BRANCH_AND_BOUND: {
        int64_t costOfChange = (34 + 68) * options.feeRate / 1000;
        auto result = BranchAndBound(eligibleCoins, targetAmount, costOfChange);
        return result.value_or(SelectionResult{false, {}, 0, targetAmount, 0, 0, algo});
    }
    case SelectionAlgorithm::SINGLE_RANDOM:
        return SingleRandomDraw(eligibleCoins, targetAmount);
    case SelectionAlgorithm::KNAPSACK:
        return Knapsack(eligibleCoins, targetAmount);
    case SelectionAlgorithm::FIFO:
        return FIFO(eligibleCoins, targetAmount);
    case SelectionAlgorithm::LARGEST_FIRST:
        return LargestFirst(eligibleCoins, targetAmount);
    default:
        return FIFO(eligibleCoins, targetAmount);
    }
}

SelectionResult PQCoinSelector::SelectForChannel(
    const std::vector<CoinOutput>& availableCoins,
    int64_t channelCapacity,
    int64_t reserve)
{
    SelectionOptions options;
    options.mode = SelectionMode::CHANNEL_FUNDING;
    options.channelFundingMode = true;
    options.channelReserve = reserve;

    // For channel funding, prefer single large UTXO to minimize
    // funding TX complexity (2-of-2 Dilithium multisig is ~5KB)
    options.algorithm = SelectionAlgorithm::LARGEST_FIRST;

    // Channel funding needs slightly more than capacity for fees
    auto& feeEstimator = PQFeeEstimator2::GetInstance();
    auto feeEstimate = feeEstimator.EstimateL2Fee(L2OperationType::CHANNEL_OPEN, channelCapacity);

    int64_t targetAmount = channelCapacity + reserve + feeEstimate.absoluteFee;

    return SelectCoins(availableCoins, targetAmount, options);
}

SelectionResult PQCoinSelector::SelectPrivate(
    const std::vector<CoinOutput>& availableCoins,
    int64_t targetAmount)
{
    SelectionOptions options;
    options.mode = SelectionMode::PRIVACY_OPTIMAL;
    options.preferPrivateOutputs = true;
    options.avoidMixingAnonSets = true;

    // For privacy, use single random draw to avoid deterministic patterns
    options.algorithm = SelectionAlgorithm::SINGLE_RANDOM;

    return SelectCoins(availableCoins, targetAmount, options);
}

SelectionResult PQCoinSelector::SelectForConsolidation(
    const std::vector<CoinOutput>& availableCoins,
    FeeRate maxFeeRate)
{
    SelectionOptions options;
    options.mode = SelectionMode::CONSOLIDATE;
    options.feeRate = maxFeeRate;
    options.algorithm = SelectionAlgorithm::FIFO;

    // Consolidate: select all coins that are profitable to spend
    std::vector<CoinOutput> profitable;
    for (const auto& coin : availableCoins) {
        int64_t effectiveValue = CalculateEffectiveValue(coin, maxFeeRate);
        if (effectiveValue > 0) {
            CoinOutput c = coin;
            c.effectiveValue = effectiveValue;
            profitable.push_back(c);
        }
    }

    if (profitable.empty()) {
        return SelectionResult{false, {}, 0, 0, 0, 0, SelectionAlgorithm::FIFO};
    }

    // Select all profitable coins
    int64_t total = std::accumulate(profitable.begin(), profitable.end(), int64_t{0},
        [](int64_t sum, const CoinOutput& c) { return sum + c.value; });

    SelectionResult result;
    result.success = true;
    result.selected = std::move(profitable);
    result.selectedTotal = total;
    result.targetAmount = 0;
    result.algorithmUsed = SelectionAlgorithm::FIFO;

    // Calculate fee for consolidation TX
    size_t txSize = 10 + (result.selected.size() * 68) + 34; // header + inputs + 1 output
    result.fee = (txSize * maxFeeRate) / 1000;
    result.change = total - result.fee;

    return result;
}

//=============================================================================
// Algorithm implementations
//=============================================================================

std::optional<SelectionResult> PQCoinSelector::BranchAndBound(
    std::vector<CoinOutput>& coins,
    int64_t targetValue,
    int64_t costOfChange,
    size_t maxIterations)
{
    // Sort by effective value descending for BnB efficiency
    std::sort(coins.begin(), coins.end(),
        [](const CoinOutput& a, const CoinOutput& b) {
            return a.effectiveValue > b.effectiveValue;
        });

    SelectionResult bestResult;
    bestResult.success = false;
    int64_t bestWaste = std::numeric_limits<int64_t>::max();

    std::vector<bool> currentSelection(coins.size(), false);
    std::vector<bool> bestSelection(coins.size(), false);

    int64_t currentValue = 0;
    size_t iterations = 0;

    // Calculate total available
    int64_t totalAvailable = std::accumulate(coins.begin(), coins.end(), int64_t{0},
        [](int64_t sum, const CoinOutput& c) { return sum + c.effectiveValue; });

    if (totalAvailable < targetValue) {
        return std::nullopt;
    }

    // BnB search
    size_t depth = 0;
    bool backtrack = false;

    while (iterations < maxIterations) {
        iterations++;

        if (backtrack) {
            // Find last included coin to exclude
            while (depth > 0 && !currentSelection[depth - 1]) {
                depth--;
            }

            if (depth == 0) {
                break; // Searched all combinations
            }

            depth--;
            currentSelection[depth] = false;
            currentValue -= coins[depth].effectiveValue;
            depth++;
            backtrack = false;
        }

        if (depth >= coins.size()) {
            backtrack = true;
            continue;
        }

        // Try including current coin
        int64_t tentativeValue = currentValue + coins[depth].effectiveValue;

        // Check if this exceeds target + acceptable waste
        if (tentativeValue > targetValue + costOfChange) {
            // Skip this coin and continue
            currentSelection[depth] = false;

            // Calculate remaining available
            int64_t remaining = 0;
            for (size_t i = depth + 1; i < coins.size(); i++) {
                remaining += coins[i].effectiveValue;
            }

            if (currentValue + remaining < targetValue) {
                backtrack = true;
            } else {
                depth++;
            }
            continue;
        }

        // Include this coin
        currentSelection[depth] = true;
        currentValue = tentativeValue;

        // Check if we've reached target
        if (currentValue >= targetValue) {
            int64_t waste = currentValue - targetValue;

            // Prefer exact match (no change needed)
            if (waste == 0) {
                // Perfect match!
                SelectionResult result;
                result.success = true;
                result.targetAmount = targetValue;
                result.algorithmUsed = SelectionAlgorithm::BRANCH_AND_BOUND;

                for (size_t i = 0; i < coins.size(); i++) {
                    if (currentSelection[i]) {
                        result.selected.push_back(coins[i]);
                    }
                }
                result.selectedTotal = currentValue;
                result.change = 0;
                result.fee = 0; // Caller should calculate

                return result;
            }

            // Otherwise, record if best so far
            if (waste < bestWaste) {
                bestWaste = waste;
                bestSelection = currentSelection;
                bestResult.success = true;
                bestResult.targetAmount = targetValue;
                bestResult.algorithmUsed = SelectionAlgorithm::BRANCH_AND_BOUND;
            }

            backtrack = true;
            continue;
        }

        depth++;
    }

    if (bestResult.success) {
        bestResult.selected.clear();
        int64_t total = 0;
        for (size_t i = 0; i < coins.size(); i++) {
            if (bestSelection[i]) {
                bestResult.selected.push_back(coins[i]);
                total += coins[i].effectiveValue;
            }
        }
        bestResult.selectedTotal = total;
        bestResult.change = total - targetValue;
        return bestResult;
    }

    return std::nullopt;
}

SelectionResult PQCoinSelector::SingleRandomDraw(
    const std::vector<CoinOutput>& coins,
    int64_t targetValue)
{
    SelectionResult result;
    result.targetAmount = targetValue;
    result.algorithmUsed = SelectionAlgorithm::SINGLE_RANDOM;

    // Shuffle coins randomly
    std::vector<CoinOutput> shuffled = coins;
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(shuffled.begin(), shuffled.end(), g);

    // Select until target reached
    int64_t currentValue = 0;
    for (const auto& coin : shuffled) {
        result.selected.push_back(coin);
        currentValue += coin.effectiveValue;

        if (currentValue >= targetValue) {
            break;
        }
    }

    if (currentValue >= targetValue) {
        result.success = true;
        result.selectedTotal = currentValue;
        result.change = currentValue - targetValue;
    } else {
        result.success = false;
    }

    return result;
}

SelectionResult PQCoinSelector::Knapsack(
    const std::vector<CoinOutput>& coins,
    int64_t targetValue)
{
    // Simplified knapsack using approximation
    // Full DP would be O(n * target) which may be too large

    SelectionResult result;
    result.targetAmount = targetValue;
    result.algorithmUsed = SelectionAlgorithm::KNAPSACK;

    // Sort by value descending
    std::vector<CoinOutput> sorted = coins;
    std::sort(sorted.begin(), sorted.end(),
        [](const CoinOutput& a, const CoinOutput& b) {
            return a.effectiveValue > b.effectiveValue;
        });

    // Greedy approximation with look-ahead
    int64_t currentValue = 0;
    std::vector<size_t> selectedIndices;

    for (size_t i = 0; i < sorted.size(); i++) {
        if (currentValue >= targetValue) {
            break;
        }

        // Include this coin if it helps
        if (currentValue + sorted[i].effectiveValue <= targetValue * 2) {
            selectedIndices.push_back(i);
            currentValue += sorted[i].effectiveValue;
        }
    }

    if (currentValue >= targetValue) {
        result.success = true;
        for (size_t idx : selectedIndices) {
            result.selected.push_back(sorted[idx]);
        }
        result.selectedTotal = currentValue;
        result.change = currentValue - targetValue;
    } else {
        result.success = false;
    }

    return result;
}

SelectionResult PQCoinSelector::FIFO(
    std::vector<CoinOutput> coins,
    int64_t targetValue)
{
    SelectionResult result;
    result.targetAmount = targetValue;
    result.algorithmUsed = SelectionAlgorithm::FIFO;

    // Sort by block height (oldest first)
    std::sort(coins.begin(), coins.end(),
        [](const CoinOutput& a, const CoinOutput& b) {
            return a.blockHeight < b.blockHeight;
        });

    int64_t currentValue = 0;
    for (const auto& coin : coins) {
        result.selected.push_back(coin);
        currentValue += coin.effectiveValue;

        if (currentValue >= targetValue) {
            break;
        }
    }

    if (currentValue >= targetValue) {
        result.success = true;
        result.selectedTotal = currentValue;
        result.change = currentValue - targetValue;
    } else {
        result.success = false;
    }

    return result;
}

SelectionResult PQCoinSelector::LargestFirst(
    std::vector<CoinOutput> coins,
    int64_t targetValue)
{
    SelectionResult result;
    result.targetAmount = targetValue;
    result.algorithmUsed = SelectionAlgorithm::LARGEST_FIRST;

    // Sort by value descending
    std::sort(coins.begin(), coins.end(),
        [](const CoinOutput& a, const CoinOutput& b) {
            return a.effectiveValue > b.effectiveValue;
        });

    int64_t currentValue = 0;
    for (const auto& coin : coins) {
        result.selected.push_back(coin);
        currentValue += coin.effectiveValue;

        if (currentValue >= targetValue) {
            break;
        }
    }

    if (currentValue >= targetValue) {
        result.success = true;
        result.selectedTotal = currentValue;
        result.change = currentValue - targetValue;
    } else {
        result.success = false;
    }

    return result;
}

//=============================================================================
// Utility functions
//=============================================================================

int64_t PQCoinSelector::CalculateEffectiveValue(
    const CoinOutput& coin,
    FeeRate feeRate)
{
    // Cost to spend a Dilithium UTXO:
    // - Input: ~2420 bytes (signature) + 36 bytes (outpoint) = ~2456 bytes
    // For PQ, signatures dominate input cost
    constexpr size_t PQ_INPUT_SIZE = 2500; // Conservative estimate

    int64_t costToSpend = (PQ_INPUT_SIZE * feeRate) / 1000;
    return coin.value - costToSpend;
}

std::vector<CoinOutput> PQCoinSelector::FilterCoins(
    const std::vector<CoinOutput>& coins,
    const SelectionOptions& options)
{
    std::vector<CoinOutput> filtered;

    for (const auto& coin : coins) {
        // Check confirmation depth
        if (coin.confirmations < options.minConfirmations) {
            continue;
        }

        // Check asset filter
        if (!options.selectAssetId.empty() && coin.assetId != options.selectAssetId) {
            continue;
        }

        // Check dust
        if (coin.value < options.dustThreshold) {
            continue;
        }

        // Privacy mode: prefer private outputs
        if (options.preferPrivateOutputs && !coin.isPrivate) {
            // Still include, but de-prioritize (could implement scoring)
        }

        filtered.push_back(coin);
    }

    return filtered;
}

bool PQCoinSelector::MeetsPrivacyRequirements(
    const std::vector<CoinOutput>& selected,
    const SelectionOptions& options)
{
    if (!options.avoidMixingAnonSets) {
        return true;
    }

    // Check that all selected coins are from the same anonymity set
    if (selected.size() <= 1) {
        return true;
    }

    uint32_t firstAnonSet = selected[0].anonSetId;
    for (size_t i = 1; i < selected.size(); i++) {
        if (selected[i].anonSetId != firstAnonSet) {
            return false; // Mixing anonymity sets
        }
    }

    return true;
}

} // namespace pqwallet
} // namespace soqucoin
