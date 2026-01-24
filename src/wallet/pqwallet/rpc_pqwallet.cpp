// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file rpc_pqwallet.cpp
 * @brief RPC commands for post-quantum wallet operations
 *
 * Provides CLI/RPC interface to PQ wallet functionality:
 * - pqgetnewaddress: Generate new Dilithium address
 * - pqgetaddressinfo: Get address details
 * - pqsignmessage: Sign message with Dilithium
 * - pqverifymessage: Verify Dilithium signature
 * - pqgetkeyinfo: Get key derivation info
 *
 * Design follows Bitcoin Core RPC patterns for auditor familiarity.
 *
 * @see doc/WALLET_API_SPEC.md for API documentation
 */

#include "rpc/server.h"
#include "wallet/pqwallet/pqaddress.h"
#include "wallet/pqwallet/pqcoinselection.h"
#include "wallet/pqwallet/pqcost.h"
#include "wallet/pqwallet/pqfee.h"
#include "wallet/pqwallet/pqkeys.h"
#include "wallet/pqwallet/pqwallet.h"

#include <univalue.h>

using namespace soqucoin::pqwallet;

namespace
{

// Error codes for PQ wallet operations
constexpr int RPC_PQ_WALLET_ERROR = -4001;
constexpr int RPC_PQ_ADDRESS_ERROR = -4002;
// Reserved for future pqsignmessage/pqverifymessage commands:
// constexpr int RPC_PQ_SIGN_ERROR = -4003;
// constexpr int RPC_PQ_VERIFY_ERROR = -4004;

/**
 * @brief pqgetnewaddress - Generate new post-quantum address
 *
 * Returns a new Bech32m address secured by Dilithium signature scheme.
 */
UniValue pqgetnewaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            "pqgetnewaddress ( \"network\" )\n"
            "\nGenerate a new post-quantum Dilithium address.\n"
            "\nArguments:\n"
            "1. \"network\"     (string, optional, default=\"testnet\") Network: mainnet, testnet, stagenet\n"
            "\nResult:\n"
            "{\n"
            "  \"address\": \"sq1...\",        (string) The new Bech32m address\n"
            "  \"pubkey_hash\": \"...\",       (string) BLAKE2b-160 hash of public key\n"
            "  \"network\": \"testnet\",       (string) Network identifier\n"
            "  \"type\": \"P2PQ\"              (string) Address type (P2PQ = Pay-to-Post-Quantum)\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("pqgetnewaddress", "") + HelpExampleCli("pqgetnewaddress", "\"mainnet\"") + HelpExampleRpc("pqgetnewaddress", "\"testnet\""));
    }

    // Parse network parameter
    Network network = Network::Testnet;
    if (!request.params.empty()) {
        std::string netStr = request.params[0].get_str();
        if (netStr == "mainnet") {
            network = Network::Mainnet;
        } else if (netStr == "stagenet") {
            network = Network::Stagenet;
        } else if (netStr != "testnet") {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Invalid network: must be mainnet, testnet, or stagenet");
        }
    }

    // Generate new keypair
    auto keypair = PQKeyPair::Generate();
    if (!keypair) {
        throw JSONRPCError(RPC_PQ_WALLET_ERROR, "Failed to generate Dilithium keypair");
    }

    // Get public key and hash
    auto pubkey = keypair->GetPublicKey();
    auto pubkeyHash = PQAddress::HashPublicKey(pubkey);

    // Encode address
    std::string address = PQAddress::Encode(pubkey, network, AddressType::P2PQ);
    if (address.empty()) {
        throw JSONRPCError(RPC_PQ_ADDRESS_ERROR, "Failed to encode address");
    }

    // Build result
    UniValue result(UniValue::VOBJ);
    result.pushKV("address", address);

    // Convert hash to hex string
    std::string hashHex;
    for (uint8_t b : pubkeyHash) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        hashHex += buf;
    }
    result.pushKV("pubkey_hash", hashHex);

    result.pushKV("network", network == Network::Mainnet ? "mainnet" :
                             network == Network::Testnet ? "testnet" :
                                                           "stagenet");
    result.pushKV("type", "P2PQ");

    return result;
}

/**
 * @brief pqvalidateaddress - Validate a post-quantum address
 */
UniValue pqvalidateaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "pqvalidateaddress \"address\"\n"
            "\nValidate a Soqucoin post-quantum address.\n"
            "\nArguments:\n"
            "1. \"address\"     (string, required) The Bech32m address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\": true|false,       (boolean) If the address is valid\n"
            "  \"network\": \"testnet\",       (string) Detected network\n"
            "  \"type\": \"P2PQ\",             (string) Address type\n"
            "  \"pubkey_hash\": \"...\",       (string) Decoded public key hash\n"
            "  \"error\": \"...\"              (string) Error message if invalid\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("pqvalidateaddress", "\"tsq1...\"") + HelpExampleRpc("pqvalidateaddress", "\"sq1...\""));
    }

    std::string address = request.params[0].get_str();

    UniValue result(UniValue::VOBJ);

    bool isValid = PQAddress::IsValid(address);
    result.pushKV("isvalid", isValid);

    if (isValid) {
        Network network = PQAddress::DetectNetwork(address);
        result.pushKV("network", network == Network::Mainnet ? "mainnet" :
                                 network == Network::Testnet ? "testnet" :
                                                               "stagenet");

        auto info = PQAddress::Decode(address);
        if (info.valid) {
            // Convert hash to hex
            std::string hashHex;
            for (uint8_t b : info.hash) {
                char buf[3];
                snprintf(buf, sizeof(buf), "%02x", b);
                hashHex += buf;
            }
            result.pushKV("pubkey_hash", hashHex);
            result.pushKV("type", info.type == AddressType::P2PQ     ? "P2PQ" :
                                  info.type == AddressType::P2PQ_PAT ? "P2PQ_PAT" :
                                                                       "P2SH_PQ");
        }
    } else {
        result.pushKV("error", "Invalid address format");
    }

    return result;
}

/**
 * @brief pqestimatefeerate - Estimate fee for PQ transaction
 */
UniValue pqestimatefeerate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            "pqestimatefeerate ( num_inputs num_outputs )\n"
            "\nEstimate verification cost for a PQ transaction.\n"
            "\nArguments:\n"
            "1. num_inputs      (numeric, optional, default=1) Number of inputs\n"
            "2. num_outputs     (numeric, optional, default=2) Number of outputs\n"
            "\nResult:\n"
            "{\n"
            "  \"verify_cost\": 123,          (numeric) Total verification cost in units\n"
            "  \"breakdown\": {...},          (object) Cost breakdown by component\n"
            "  \"recommendation\": \"...\"     (string) Optimization recommendation\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("pqestimatefeerate", "") + HelpExampleCli("pqestimatefeerate", "5 10") + HelpExampleRpc("pqestimatefeerate", "1, 2"));
    }

    uint32_t numInputs = 1;
    uint32_t numOutputs = 2;

    if (request.params.size() > 0 && !request.params[0].isNull()) {
        if (request.params[0].isNum()) {
            numInputs = request.params[0].get_int();
        } else {
            numInputs = std::stoi(request.params[0].get_str());
        }
    }
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        if (request.params[1].isNum()) {
            numOutputs = request.params[1].get_int();
        } else {
            numOutputs = std::stoi(request.params[1].get_str());
        }
    }

    // Calculate verification cost using per-input cost formula
    // Each input requires one Dilithium signature verification
    uint32_t signatureCost = numInputs * VerifyCost::DILITHIUM;
    uint32_t scriptCost = (numInputs + numOutputs) * 2; // Script ops
    uint32_t hashCost = numInputs * 2;                  // Hash operations
    uint32_t totalCost = signatureCost + scriptCost + hashCost;

    UniValue result(UniValue::VOBJ);
    result.pushKV("verify_cost", static_cast<int64_t>(totalCost));

    UniValue breakdown(UniValue::VOBJ);
    breakdown.pushKV("signature_cost", static_cast<int64_t>(signatureCost));
    breakdown.pushKV("script_cost", static_cast<int64_t>(scriptCost));
    breakdown.pushKV("hash_cost", static_cast<int64_t>(hashCost));
    result.pushKV("breakdown", breakdown);

    // Recommendation based on input count
    std::string recommendation;
    if (numInputs >= 20) {
        recommendation = "Consider using PAT aggregation for " +
                         std::to_string(static_cast<int>((1.0 - 20.0 / numInputs) * 100)) + "% savings";
    } else {
        recommendation = "Standard transaction, no aggregation needed";
    }
    result.pushKV("recommendation", recommendation);

    return result;
}

/**
 * @brief pqwalletinfo - Get PQ wallet information
 */
UniValue pqwalletinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "pqwalletinfo\n"
            "\nGet post-quantum wallet information and status.\n"
            "\nResult:\n"
            "{\n"
            "  \"version\": \"1.0\",           (string) Wallet library version\n"
            "  \"dilithium_mode\": \"ML-DSA-44\", (string) Dilithium security level\n"
            "  \"address_format\": \"Bech32m\", (string) Address encoding format\n"
            "  \"encryption\": \"AES-256-CBC+HMAC\", (string) File encryption method\n"
            "  \"kdf\": \"PBKDF2-SHA256\",     (string) Key derivation function\n"
            "  \"features\": {...}            (object) Feature status\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("pqwalletinfo", "") + HelpExampleRpc("pqwalletinfo", ""));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("version", "1.0");
    result.pushKV("dilithium_mode", "ML-DSA-44");
    result.pushKV("pubkey_size", 1312);
    result.pushKV("signature_size", 2420);
    result.pushKV("address_format", "Bech32m");
    result.pushKV("encryption", "AES-256-CBC+HMAC");
    result.pushKV("kdf", "Argon2id");
    result.pushKV("kdf_params", "t=3,m=64MB,p=4");

    UniValue features(UniValue::VOBJ);
    features.pushKV("pat_aggregation", true);
    features.pushKV("bppp_batching", true);
    features.pushKV("hardware_wallet_ready", false);
    features.pushKV("l2_lightning_ready", true);
    features.pushKV("coin_selection", "BnB");
    features.pushKV("watch_only", true);
    result.pushKV("features", features);

    return result;
}

/**
 * @brief pqestimatefee - Block-aware fee estimation with L2 support
 */
UniValue pqestimatefee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            "pqestimatefee ( conf_target \"priority\" )\n"
            "\nEstimate smart fee with L2 Lightning support.\n"
            "\nArguments:\n"
            "1. conf_target    (numeric, optional, default=6) Target confirmation blocks (1-1008)\n"
            "2. \"priority\"     (string, optional, default=\"normal\") urgent|normal|economy\n"
            "\nResult:\n"
            "{\n"
            "  \"feerate\": 10000,           (numeric) Fee rate in sat/vB\n"
            "  \"conf_target\": 6,           (numeric) Target confirmation blocks\n"
            "  \"confidence\": 0.95,         (numeric) Estimation confidence (0-1)\n"
            "  \"congestion\": 0.5,          (numeric) Mempool congestion level (0-1)\n"
            "  \"l2_fees\": {...}            (object) Lightning channel operation fees\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("pqestimatefee", "") +
            HelpExampleCli("pqestimatefee", "2 \"urgent\"") +
            HelpExampleRpc("pqestimatefee", "6, \"normal\""));
    }

    uint32_t confTarget = 6;
    std::string priority = "normal";

    if (request.params.size() > 0 && !request.params[0].isNull()) {
        if (request.params[0].isNum()) {
            confTarget = request.params[0].get_int();
        } else {
            confTarget = std::stoi(request.params[0].get_str());
        }
    }
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        priority = request.params[1].get_str();
    }

    auto& estimator = PQFeeEstimator2::GetInstance();
    estimator.UpdateFromMempool();

    FeeEstimateMode mode = FeeEstimateMode::CONSERVATIVE;
    if (priority == "urgent" || priority == "high") {
        mode = FeeEstimateMode::CONSERVATIVE;
        confTarget = std::min(confTarget, 2u);
    } else if (priority == "economy" || priority == "low") {
        mode = FeeEstimateMode::ECONOMICAL;
        confTarget = std::max(confTarget, 12u);
    }

    auto estimate = estimator.EstimateFee(confTarget, mode);

    UniValue result(UniValue::VOBJ);
    result.pushKV("feerate", estimate.feeRate);
    result.pushKV("conf_target", static_cast<int64_t>(estimate.confTarget));
    result.pushKV("confidence", estimate.confidence);
    result.pushKV("congestion", estimator.GetMempoolCongestion());

    // L2 fee estimates
    UniValue l2Fees(UniValue::VOBJ);
    auto channelOpen = estimator.EstimateL2Fee(L2OperationType::CHANNEL_OPEN);
    auto channelClose = estimator.EstimateL2Fee(L2OperationType::CHANNEL_CLOSE_COOP);
    auto forceClose = estimator.EstimateL2Fee(L2OperationType::CHANNEL_CLOSE_FORCE);

    l2Fees.pushKV("channel_open", channelOpen.absoluteFee);
    l2Fees.pushKV("channel_close", channelClose.absoluteFee);
    l2Fees.pushKV("force_close_buffer", forceClose.absoluteFee);
    result.pushKV("l2_fees", l2Fees);

    return result;
}

/**
 * @brief pqchannelreserve - Calculate L2 Lightning channel reserves
 */
UniValue pqchannelreserve(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw std::runtime_error(
            "pqchannelreserve capacity ( is_initiator )\n"
            "\nCalculate Lightning channel reserve requirements (BOLT-2).\n"
            "\nArguments:\n"
            "1. capacity       (numeric, required) Channel capacity in satoshis\n"
            "2. is_initiator   (boolean, optional, default=true) Are we opening the channel?\n"
            "\nResult:\n"
            "{\n"
            "  \"local_reserve\": 1000,      (numeric) Our committed reserve\n"
            "  \"remote_reserve\": 1000,     (numeric) Peer's required reserve\n"
            "  \"dust_limit\": 546,          (numeric) Minimum output value\n"
            "  \"htlc_minimum\": 1000,       (numeric) Minimum HTLC amount\n"
            "  \"usable_capacity\": 98000,   (numeric) Spendable capacity after reserves\n"
            "  \"is_viable\": true           (boolean) Is this channel size viable?\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("pqchannelreserve", "100000") +
            HelpExampleCli("pqchannelreserve", "1000000 false") +
            HelpExampleRpc("pqchannelreserve", "100000, true"));
    }

    int64_t capacity;
    if (request.params[0].isNum()) {
        capacity = request.params[0].get_int64();
    } else {
        capacity = std::stoll(request.params[0].get_str());
    }

    bool isInitiator = true;
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        isInitiator = request.params[1].get_bool();
    }

    auto& estimator = PQFeeEstimator2::GetInstance();
    auto reserve = estimator.CalculateChannelReserve(capacity, isInitiator);
    bool isViable = estimator.IsViableChannelCapacity(capacity);

    UniValue result(UniValue::VOBJ);
    result.pushKV("local_reserve", reserve.localReserve);
    result.pushKV("remote_reserve", reserve.remoteReserve);
    result.pushKV("dust_limit", reserve.dustLimit);
    result.pushKV("htlc_minimum", reserve.htlcMinimum);
    result.pushKV("max_htlc_in_flight", reserve.maxHtlcInFlight);
    result.pushKV("usable_capacity", reserve.UsableCapacity(capacity));
    result.pushKV("is_viable", isViable);

    return result;
}

/**
 * @brief pqselectcoins - Select optimal UTXOs for a transaction
 */
UniValue pqselectcoins(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3) {
        throw std::runtime_error(
            "pqselectcoins amount ( \"mode\" feerate )\n"
            "\nSelect optimal coins for a transaction amount.\n"
            "\nArguments:\n"
            "1. amount         (numeric, required) Target amount in satoshis\n"
            "2. \"mode\"         (string, optional, default=\"normal\") Selection mode:\n"
            "                   normal - Standard fee optimization\n"
            "                   channel - L2 channel funding (largest UTXO)\n"
            "                   privacy - Stage 4 privacy-preserving\n"
            "                   consolidate - Reduce UTXO count\n"
            "3. feerate        (numeric, optional, default=10000) Fee rate in sat/vB\n"
            "\nResult:\n"
            "{\n"
            "  \"success\": true,            (boolean) Selection succeeded\n"
            "  \"algorithm\": \"BnB\",         (string) Algorithm used\n"
            "  \"inputs\": 2,                (numeric) Number of inputs selected\n"
            "  \"selected_total\": 150000,   (numeric) Total value of selected\n"
            "  \"target\": 100000,           (numeric) Target amount\n"
            "  \"fee\": 1500,                (numeric) Estimated fee\n"
            "  \"change\": 48500,            (numeric) Change amount\n"
            "  \"waste\": 340                (numeric) Waste metric\n"
            "}\n"
            "\nNote: This is a simulation. Use with actual wallet UTXOs in production.\n"
            "\nExamples:\n" +
            HelpExampleCli("pqselectcoins", "100000") +
            HelpExampleCli("pqselectcoins", "1000000 \"channel\"") +
            HelpExampleRpc("pqselectcoins", "100000, \"normal\", 10000"));
    }

    int64_t amount;
    if (request.params[0].isNum()) {
        amount = request.params[0].get_int64();
    } else {
        amount = std::stoll(request.params[0].get_str());
    }

    std::string modeStr = "normal";
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        modeStr = request.params[1].get_str();
    }

    int64_t feeRate = 10000;
    if (request.params.size() > 2 && !request.params[2].isNull()) {
        if (request.params[2].isNum()) {
            feeRate = request.params[2].get_int64();
        } else {
            feeRate = std::stoll(request.params[2].get_str());
        }
    }

    // Create simulated UTXOs for demo (real implementation reads from wallet)
    std::vector<CoinOutput> simulatedCoins;
    simulatedCoins.push_back({"tx1", 0, 50000, 100, 0, 0, 1000, false, ""});
    simulatedCoins.push_back({"tx2", 0, 100000, 50, 0, 0, 2000, false, ""});
    simulatedCoins.push_back({"tx3", 0, 200000, 25, 0, 0, 3000, false, ""});
    simulatedCoins.push_back({"tx4", 0, 500000, 10, 0, 0, 4000, false, ""});
    simulatedCoins.push_back({"tx5", 0, 1000000, 5, 0, 0, 5000, false, ""});

    SelectionOptions options;
    options.feeRate = feeRate;

    SelectionResult selResult;
    if (modeStr == "channel") {
        selResult = PQCoinSelector::SelectForChannel(simulatedCoins, amount);
    } else if (modeStr == "privacy") {
        selResult = PQCoinSelector::SelectPrivate(simulatedCoins, amount);
    } else if (modeStr == "consolidate") {
        selResult = PQCoinSelector::SelectForConsolidation(simulatedCoins, feeRate);
    } else {
        selResult = PQCoinSelector::SelectCoins(simulatedCoins, amount, options);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("success", selResult.success);

    std::string algoName;
    switch (selResult.algorithmUsed) {
    case SelectionAlgorithm::BRANCH_AND_BOUND:
        algoName = "BnB";
        break;
    case SelectionAlgorithm::SINGLE_RANDOM:
        algoName = "SRD";
        break;
    case SelectionAlgorithm::KNAPSACK:
        algoName = "Knapsack";
        break;
    case SelectionAlgorithm::FIFO:
        algoName = "FIFO";
        break;
    case SelectionAlgorithm::LARGEST_FIRST:
        algoName = "LargestFirst";
        break;
    default:
        algoName = "Unknown";
        break;
    }
    result.pushKV("algorithm", algoName);

    result.pushKV("inputs", static_cast<int64_t>(selResult.InputCount()));
    result.pushKV("selected_total", selResult.selectedTotal);
    result.pushKV("target", selResult.targetAmount);
    result.pushKV("fee", selResult.fee);
    result.pushKV("change", selResult.change);
    result.pushKV("waste", selResult.GetWaste());
    result.pushKV("exact_match", selResult.IsExactMatch());

    return result;
}

// RPC command table for PQ wallet
static const CRPCCommand pqWalletCommands[] = {
    // category    name                 actor               okSafe  argNames
    {"pqwallet", "pqgetnewaddress", &pqgetnewaddress, true, {"network"}},
    {"pqwallet", "pqvalidateaddress", &pqvalidateaddress, true, {"address"}},
    {"pqwallet", "pqestimatefeerate", &pqestimatefeerate, true, {"num_inputs", "num_outputs"}},
    {"pqwallet", "pqwalletinfo", &pqwalletinfo, true, {}},
    {"pqwallet", "pqestimatefee", &pqestimatefee, true, {"conf_target", "priority"}},
    {"pqwallet", "pqchannelreserve", &pqchannelreserve, true, {"capacity", "is_initiator"}},
    {"pqwallet", "pqselectcoins", &pqselectcoins, true, {"amount", "mode", "feerate"}},
};

} // anonymous namespace

/**
 * @brief Register PQ wallet RPC commands
 */
void RegisterPQWalletRPCCommands(CRPCTable& t)
{
    for (const auto& cmd : pqWalletCommands) {
        t.appendCommand(cmd.name, &cmd);
    }
}
