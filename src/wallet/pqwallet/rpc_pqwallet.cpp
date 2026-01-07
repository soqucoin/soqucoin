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
#include "wallet/pqwallet/pqcost.h"
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
            "  \"pubkey_hash\": \"...\",       (string) SHA3-256 hash of public key\n"
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
    result.pushKV("kdf", "PBKDF2-SHA256");
    result.pushKV("kdf_iterations", 100000);

    UniValue features(UniValue::VOBJ);
    features.pushKV("pat_aggregation", true);
    features.pushKV("bppp_batching", true);
    features.pushKV("hardware_wallet_ready", false);
    result.pushKV("features", features);

    return result;
}

// RPC command table for PQ wallet
static const CRPCCommand pqWalletCommands[] = {
    // category    name                 actor               okSafe  argNames
    {"pqwallet", "pqgetnewaddress", &pqgetnewaddress, true, {"network"}},
    {"pqwallet", "pqvalidateaddress", &pqvalidateaddress, true, {"address"}},
    {"pqwallet", "pqestimatefeerate", &pqestimatefeerate, true, {"num_inputs", "num_outputs"}},
    {"pqwallet", "pqwalletinfo", &pqwalletinfo, true, {}},
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
