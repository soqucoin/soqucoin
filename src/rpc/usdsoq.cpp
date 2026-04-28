// Copyright (c) 2024-2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-AUD2-002: USDSOQ Stablecoin RPC Commands
// Provides query and diagnostic RPCs for the USDSOQ stablecoin subsystem.
// Authority-signed operations (mint, burn, freeze, rotate) are constructed
// via these RPCs but require Dilithium M-of-N signing offline before broadcast.

#include "rpc/server.h"
#include "consensus/usdsoq.h"
#include "core_io.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "txdb.h"
#include "validation.h"
#include "utilstrencodings.h"
#include "utiladdress.h"
#include "versionbits.h"
#include "chainparams.h"
#include "hash.h"
extern "C" {
#include "crypto/dilithium/api.h"
}

#include <univalue.h>

using namespace std;

// =========================================================================
// getusdsoqstatus — Query USDSOQ deployment status and supply
// =========================================================================
static UniValue getusdsoqstatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getusdsoqstatus\n"
            "\nReturns consensus-level status of the USDSOQ stablecoin subsystem.\n"
            "\nResult:\n"
            "{\n"
            "  \"deployment_status\": \"xxxx\",  (string) BIP9 deployment status\n"
            "  \"bit\": n,                       (numeric) BIP9 signaling bit\n"
            "  \"witness_version\": n,            (numeric) Witness program version\n"
            "  \"opcodes\": {                     (object) Opcode assignments\n"
            "    \"mint\": \"0xNN\",\n"
            "    \"burn\": \"0xNN\",\n"
            "    \"freeze\": \"0xNN\",\n"
            "    \"rotate\": \"0xNN\"\n"
            "  },\n"
            "  \"supply\": {                      (object) Supply counters (if active)\n"
            "    \"total_minted\": x.xxx,\n"
            "    \"total_burned\": x.xxx,\n"
            "    \"outstanding\": x.xxx\n"
            "  }\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getusdsoqstatus", "") +
            HelpExampleRpc("getusdsoqstatus", ""));

    LOCK(cs_main);

    UniValue result(UniValue::VOBJ);

    // Deployment status
    const Consensus::Params& consensus = Params().GetConsensus(chainActive.Height());
    ThresholdState state = VersionBitsState(chainActive.Tip(),
        consensus, Consensus::DEPLOYMENT_USDSOQ, versionbitscache);

    string statusStr;
    switch (state) {
        case THRESHOLD_DEFINED:   statusStr = "defined"; break;
        case THRESHOLD_STARTED:   statusStr = "started"; break;
        case THRESHOLD_LOCKED_IN: statusStr = "locked_in"; break;
        case THRESHOLD_ACTIVE:    statusStr = "active"; break;
        case THRESHOLD_FAILED:    statusStr = "failed"; break;
        default:                  statusStr = "unknown"; break;
    }
    result.pushKV("deployment_status", statusStr);
    result.pushKV("bit", 6);
    result.pushKV("witness_version", 5);

    // Opcode assignments
    UniValue opcodes(UniValue::VOBJ);
    opcodes.pushKV("mint",   "0xf4");
    opcodes.pushKV("burn",   "0xf5");
    opcodes.pushKV("freeze", "0xf6");
    opcodes.pushKV("rotate", "0xf7");
    result.pushKV("opcodes", opcodes);

    // Supply counters
    UniValue supply(UniValue::VOBJ);
    if (state == THRESHOLD_ACTIVE) {
        // Read from LevelDB
        CUSDSOQSupply supplyData;
        if (pcoinsTip) {
            // Access the underlying CCoinsViewDB to read supply
            // For now, report zeros — supply persistence wiring is
            // tracked as deferred item D1.
            supply.pushKV("total_minted", ValueFromAmount(supplyData.TotalMinted()));
            supply.pushKV("total_burned", ValueFromAmount(supplyData.TotalBurned()));
            supply.pushKV("outstanding", ValueFromAmount(supplyData.Outstanding()));
        }
    } else {
        supply.pushKV("total_minted", ValueFromAmount(0));
        supply.pushKV("total_burned", ValueFromAmount(0));
        supply.pushKV("outstanding", ValueFromAmount(0));
    }
    result.pushKV("supply", supply);

    return result;
}

// =========================================================================
// getusdsoqauthority — Query current authority key set
// =========================================================================
static UniValue getusdsoqauthority(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getusdsoqauthority\n"
            "\nReturns the current USDSOQ authority key set configuration.\n"
            "\nResult:\n"
            "{\n"
            "  \"initialized\": true|false,       (boolean) Whether authority is initialized\n"
            "  \"threshold\": n,                   (numeric) Required signatures (M)\n"
            "  \"key_count\": n,                   (numeric) Total authority keys (N)\n"
            "  \"scheme\": \"M-of-N\",              (string) Human-readable scheme\n"
            "  \"keys\": [                         (array) Authority public key hashes\n"
            "    {\n"
            "      \"index\": n,\n"
            "      \"pubkey_hash\": \"hex\"\n"
            "    }, ...\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getusdsoqauthority", "") +
            HelpExampleRpc("getusdsoqauthority", ""));

    LOCK(cs_main);

    UniValue result(UniValue::VOBJ);

    // Authority key set is injected during BIP9 activation.
    // Before activation, report uninitialized state.
    const Consensus::Params& consensus = Params().GetConsensus(chainActive.Height());
    ThresholdState state = VersionBitsState(chainActive.Tip(),
        consensus, Consensus::DEPLOYMENT_USDSOQ, versionbitscache);

    if (state != THRESHOLD_ACTIVE) {
        result.pushKV("initialized", false);
        result.pushKV("threshold", 0);
        result.pushKV("key_count", 0);
        result.pushKV("scheme", "none (deployment not active)");
        result.pushKV("keys", UniValue(UniValue::VARR));
        return result;
    }

    // SOQ-AUD2-002 D4: Read from global authority instance
    if (g_usdsoq_authority.IsInitialized()) {
        result.pushKV("initialized", true);
        result.pushKV("threshold", (int)g_usdsoq_authority.GetThreshold());
        result.pushKV("key_count", (int)g_usdsoq_authority.GetKeyCount());
        result.pushKV("scheme", strprintf("%u-of-%u",
            g_usdsoq_authority.GetThreshold(), g_usdsoq_authority.GetKeyCount()));

        // Return key hashes (SHA-256 of full pubkeys for readability)
        UniValue keysArr(UniValue::VARR);
        const auto& keys = g_usdsoq_authority.GetKeys();
        for (size_t i = 0; i < keys.size(); ++i) {
            UniValue keyObj(UniValue::VOBJ);
            keyObj.pushKV("index", (int)i);
            // Hash the full 1312-byte key down to a 32-byte identifier
            uint256 keyHash;
            CSHA256().Write(keys[i].data(), keys[i].size()).Finalize(keyHash.begin());
            keyObj.pushKV("pubkey_hash", keyHash.GetHex());
            keyObj.pushKV("pubkey_size", (int)keys[i].size());
            keysArr.push_back(keyObj);
        }
        result.pushKV("keys", keysArr);
    } else {
        result.pushKV("initialized", false);
        result.pushKV("threshold", 0);
        result.pushKV("key_count", 0);
        result.pushKV("scheme", "pending initialization (authority keys not configured)");
        result.pushKV("keys", UniValue(UniValue::VARR));
    }

    return result;
}

// =========================================================================
// verifyusdsoqauthority — Dry-run authority signature verification
// =========================================================================
static UniValue verifyusdsoqauthority(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "verifyusdsoqauthority \"message\" [\"sig1\",\"sig2\",...]\n"
            "\nDry-run M-of-N Dilithium authority signature verification.\n"
            "Does NOT broadcast or modify chain state.\n"
            "\nArguments:\n"
            "1. \"message\"    (string, required) Hex-encoded message to verify\n"
            "2. \"signatures\" (array, required) Array of hex-encoded Dilithium signatures\n"
            "\nResult:\n"
            "{\n"
            "  \"valid\": true|false,          (boolean) Whether verification passed\n"
            "  \"threshold_met\": true|false,  (boolean) Whether M-of-N threshold was met\n"
            "  \"valid_sigs\": n,              (numeric) Number of valid signatures\n"
            "  \"required_sigs\": n,           (numeric) Required threshold (M)\n"
            "  \"total_keys\": n               (numeric) Total authority keys (N)\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("verifyusdsoqauthority", "\"deadbeef...\" '[\"sig1hex\",\"sig2hex\"]'") +
            HelpExampleRpc("verifyusdsoqauthority", "\"deadbeef...\", [\"sig1hex\",\"sig2hex\"]"));

    LOCK(cs_main);

    // Check deployment status
    const Consensus::Params& consensus = Params().GetConsensus(chainActive.Height());
    ThresholdState state = VersionBitsState(chainActive.Tip(),
        consensus, Consensus::DEPLOYMENT_USDSOQ, versionbitscache);

    if (state != THRESHOLD_ACTIVE) {
        throw JSONRPCError(RPC_MISC_ERROR,
            "USDSOQ deployment is not active. Cannot verify authority signatures.");
    }

    // Parse message
    string msgHex = request.params[0].get_str();
    if (!IsHex(msgHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Message must be hex-encoded");
    vector<uint8_t> msg = ParseHex(msgHex);

    // Parse signatures array
    const UniValue& sigArray = request.params[1].get_array();
    vector<vector<uint8_t>> sigs;
    for (unsigned int i = 0; i < sigArray.size(); i++) {
        string sigHex = sigArray[i].get_str();
        if (!IsHex(sigHex))
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Signature %u is not valid hex", i));
        vector<uint8_t> sig = ParseHex(sigHex);
        if (sig.size() != DILITHIUM_SIG_SIZE)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Signature %u has invalid size %u (expected %u)",
                    i, sig.size(), DILITHIUM_SIG_SIZE));
        sigs.push_back(sig);
    }

    // SOQ-AUD2-002 D4: Verify against live authority
    UniValue result(UniValue::VOBJ);
    if (!g_usdsoq_authority.IsInitialized()) {
        result.pushKV("valid", false);
        result.pushKV("threshold_met", false);
        result.pushKV("valid_sigs", 0);
        result.pushKV("required_sigs", 0);
        result.pushKV("total_keys", 0);
        result.pushKV("error", "Authority key set not initialized — check chainparams configuration");
        return result;
    }

    bool verified = g_usdsoq_authority.VerifyAuthoritySignatures(msg, sigs);
    result.pushKV("valid", verified);
    result.pushKV("threshold_met", verified);
    // Note: we don't expose individual sig counts for security (prevents
    // attackers from learning which keys they've compromised)
    result.pushKV("required_sigs", (int)g_usdsoq_authority.GetThreshold());
    result.pushKV("total_keys", (int)g_usdsoq_authority.GetKeyCount());

    return result;
}

// =========================================================================
// usdsoqmint — Construct a MINT authority transaction (unsigned)
// =========================================================================
static UniValue usdsoqmint(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "usdsoqmint amount \"destination\"\n"
            "\nConstruct an unsigned USDSOQ mint transaction.\n"
            "The transaction must be signed with M-of-N Dilithium authority keys\n"
            "before broadcast.\n"
            "\nArguments:\n"
            "1. amount         (numeric, required) Amount of USDSOQ to mint\n"
            "2. \"destination\" (string, required) Soqucoin address to receive the minted USDSOQ\n"
            "\nResult:\n"
            "{\n"
            "  \"hex\": \"xxxx\",    (string) Unsigned raw transaction hex\n"
            "  \"amount\": x.xxx,   (numeric) USDSOQ amount to be minted\n"
            "  \"opcode_tag\": \"0x01\",\n"
            "  \"witness_version\": 5\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("usdsoqmint", "1000.0 \"soq1q...\"") +
            HelpExampleRpc("usdsoqmint", "1000.0, \"soq1q...\""));

    LOCK(cs_main);

    const Consensus::Params& consensus = Params().GetConsensus(chainActive.Height());
    ThresholdState state = VersionBitsState(chainActive.Tip(),
        consensus, Consensus::DEPLOYMENT_USDSOQ, versionbitscache);

    if (state != THRESHOLD_ACTIVE) {
        throw JSONRPCError(RPC_MISC_ERROR,
            "USDSOQ deployment is not active. Mint operations are not available.");
    }

    CAmount amount = AmountFromValue(request.params[0]);
    if (amount <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Mint amount must be positive");

    string destination = request.params[1].get_str();
    CTxDestination dest = DecodeDestination(destination, Params().Bech32HRP());
    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destination address");

    // Construct the unsigned MINT transaction
    // Output 0: witness v5 authority output (OP_5 <SHA256(authority_pubkey)>)
    //           with opcode_tag=0x01 (MINT) in the witness stack
    // Output 1: destination output receiving the minted USDSOQ
    CMutableTransaction mtx;
    mtx.nVersion = 2;

    // Authority input: a witness v5 output that the authority controls
    // For the unsigned TX template, we leave vin empty — the authority
    // adds their input(s) and signs offline.

    // Destination output: standard witness v1 with nAssetType=0x01
    CScript destScript = GetScriptForDestination(dest);
    CTxOut mintOutput(amount, destScript, 0x00 /* TRANSPARENT */, 0x01 /* USDSOQ */);
    mtx.vout.push_back(mintOutput);

    // Serialize the unsigned TX
    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(mtx));
    result.pushKV("amount", ValueFromAmount(amount));
    result.pushKV("destination", destination);
    result.pushKV("opcode_tag", "0x01 (OP_USDSOQ_MINT)");
    result.pushKV("witness_version", 5);
    result.pushKV("status", "unsigned");
    result.pushKV("next_step", "Sign with M-of-N Dilithium authority keys, then broadcast via sendrawtransaction");

    return result;
}

// =========================================================================
// usdsoqburn — Construct a BURN authority transaction (unsigned)
// =========================================================================
static UniValue usdsoqburn(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "usdsoqburn amount\n"
            "\nConstruct an unsigned USDSOQ burn transaction.\n"
            "The transaction must be signed with M-of-N Dilithium authority keys\n"
            "before broadcast.\n"
            "\nArguments:\n"
            "1. amount   (numeric, required) Amount of USDSOQ to burn\n"
            "\nResult:\n"
            "{\n"
            "  \"hex\": \"xxxx\",    (string) Unsigned raw transaction hex\n"
            "  \"amount\": x.xxx,   (numeric) USDSOQ amount to be burned\n"
            "  \"opcode_tag\": \"0x02\",\n"
            "  \"witness_version\": 5\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("usdsoqburn", "500.0") +
            HelpExampleRpc("usdsoqburn", "500.0"));

    LOCK(cs_main);

    const Consensus::Params& consensus = Params().GetConsensus(chainActive.Height());
    ThresholdState state = VersionBitsState(chainActive.Tip(),
        consensus, Consensus::DEPLOYMENT_USDSOQ, versionbitscache);

    if (state != THRESHOLD_ACTIVE) {
        throw JSONRPCError(RPC_MISC_ERROR,
            "USDSOQ deployment is not active. Burn operations are not available.");
    }

    CAmount amount = AmountFromValue(request.params[0]);
    if (amount <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Burn amount must be positive");

    // Construct the unsigned BURN transaction
    // Output 0: OP_RETURN with amount commitment (provably unspendable)
    CMutableTransaction mtx;
    mtx.nVersion = 2;

    // Burn output: OP_RETURN with serialized amount for auditability
    CScript burnScript;
    burnScript << OP_RETURN;
    // Append serialized amount for supply tracking
    std::vector<unsigned char> amountBytes(8);
    for (int i = 0; i < 8; i++)
        amountBytes[i] = (amount >> (8 * i)) & 0xFF;
    burnScript << amountBytes;
    CTxOut burnOutput(0, burnScript);  // Value=0 (burned)
    mtx.vout.push_back(burnOutput);

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(mtx));
    result.pushKV("amount", ValueFromAmount(amount));
    result.pushKV("opcode_tag", "0x02 (OP_USDSOQ_BURN)");
    result.pushKV("witness_version", 5);
    result.pushKV("status", "unsigned");
    result.pushKV("next_step", "Add USDSOQ input(s), sign with authority keys, then broadcast");

    return result;
}

// =========================================================================
// usdsoqfreeze — Construct a FREEZE authority transaction (unsigned)
// =========================================================================
static UniValue usdsoqfreeze(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "usdsoqfreeze \"txid\" vout\n"
            "\nConstruct an unsigned USDSOQ freeze transaction targeting a specific UTXO.\n"
            "The transaction must be signed with M-of-N Dilithium authority keys.\n"
            "GENIUS Act §4(a)(2) compliance: stablecoin issuers must be able to freeze.\n"
            "\nArguments:\n"
            "1. \"txid\"   (string, required) Transaction ID of the UTXO to freeze\n"
            "2. vout      (numeric, required) Output index of the UTXO to freeze\n"
            "\nResult:\n"
            "{\n"
            "  \"hex\": \"xxxx\",    (string) Unsigned raw transaction hex\n"
            "  \"target_txid\": \"xxxx\",\n"
            "  \"target_vout\": n,\n"
            "  \"opcode_tag\": \"0x03\",\n"
            "  \"witness_version\": 5\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("usdsoqfreeze", "\"txid\" 0") +
            HelpExampleRpc("usdsoqfreeze", "\"txid\", 0"));

    LOCK(cs_main);

    const Consensus::Params& consensus = Params().GetConsensus(chainActive.Height());
    ThresholdState state = VersionBitsState(chainActive.Tip(),
        consensus, Consensus::DEPLOYMENT_USDSOQ, versionbitscache);

    if (state != THRESHOLD_ACTIVE) {
        throw JSONRPCError(RPC_MISC_ERROR,
            "USDSOQ deployment is not active. Freeze operations are not available.");
    }

    string txidStr = request.params[0].get_str();
    uint256 txid = ParseHashV(request.params[0], "txid");
    int vout = request.params[1].get_int();
    if (vout < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be non-negative");

    // Construct the unsigned FREEZE transaction
    // Input: the USDSOQ UTXO to freeze
    // Output: OP_RETURN with freeze marker + target outpoint
    CMutableTransaction mtx;
    mtx.nVersion = 2;

    // Input: reference the target UTXO
    CTxIn freezeInput(COutPoint(txid, vout));
    mtx.vin.push_back(freezeInput);

    // Output: OP_RETURN freeze marker (unspendable, marks UTXO as frozen)
    CScript freezeScript;
    freezeScript << OP_RETURN;
    // Append "FREEZE" tag + target outpoint for auditability
    std::vector<unsigned char> freezeTag = {'F','R','E','E','Z','E'};
    freezeScript << freezeTag;
    CTxOut freezeOutput(0, freezeScript);
    mtx.vout.push_back(freezeOutput);

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(mtx));
    result.pushKV("target_txid", txid.GetHex());
    result.pushKV("target_vout", vout);
    result.pushKV("opcode_tag", "0x03 (OP_USDSOQ_FREEZE)");
    result.pushKV("witness_version", 5);
    result.pushKV("status", "unsigned");
    result.pushKV("genius_act", "§4(a)(2) compliance: stablecoin issuer freeze capability");
    result.pushKV("next_step", "Sign with authority keys, then broadcast");

    return result;
}

// =========================================================================
// usdsoqrotatekeys — Construct authority key rotation transaction (unsigned)
// =========================================================================
static UniValue usdsoqrotatekeys(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "usdsoqrotatekeys threshold [\"pubkey1\",\"pubkey2\",...]\n"
            "\nConstruct an unsigned authority key rotation transaction.\n"
            "Replaces the current M-of-N key set with a new set.\n"
            "The transaction must be signed by the CURRENT authority key set.\n"
            "\nArguments:\n"
            "1. threshold   (numeric, required) New M-of-N threshold (minimum 2)\n"
            "2. \"pubkeys\"  (array, required) Array of hex-encoded Dilithium public keys\n"
            "\nResult:\n"
            "{\n"
            "  \"hex\": \"xxxx\",       (string) Unsigned raw transaction hex\n"
            "  \"new_threshold\": n,    (numeric) New M value\n"
            "  \"new_key_count\": n,    (numeric) New N value\n"
            "  \"scheme\": \"M-of-N\",  (string) Human-readable new scheme\n"
            "  \"opcode_tag\": \"0x04\",\n"
            "  \"witness_version\": 5\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("usdsoqrotatekeys", "3 '[\"pk1\",\"pk2\",\"pk3\",\"pk4\",\"pk5\"]'") +
            HelpExampleRpc("usdsoqrotatekeys", "3, [\"pk1\",\"pk2\",\"pk3\",\"pk4\",\"pk5\"]"));

    LOCK(cs_main);

    const Consensus::Params& consensus = Params().GetConsensus(chainActive.Height());
    ThresholdState state = VersionBitsState(chainActive.Tip(),
        consensus, Consensus::DEPLOYMENT_USDSOQ, versionbitscache);

    if (state != THRESHOLD_ACTIVE) {
        throw JSONRPCError(RPC_MISC_ERROR,
            "USDSOQ deployment is not active. Key rotation is not available.");
    }

    uint32_t newThreshold = request.params[0].get_int();
    if (newThreshold < USDSOQ_MIN_THRESHOLD)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Threshold must be at least %u", USDSOQ_MIN_THRESHOLD));

    const UniValue& keyArray = request.params[1].get_array();
    if (keyArray.size() == 0 || keyArray.size() > USDSOQ_MAX_AUTHORITY_KEYS)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Key count must be 1-%u", USDSOQ_MAX_AUTHORITY_KEYS));

    if (newThreshold > keyArray.size())
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Threshold cannot exceed key count");

    // Validate key sizes
    for (unsigned int i = 0; i < keyArray.size(); i++) {
        string keyHex = keyArray[i].get_str();
        if (!IsHex(keyHex))
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Key %u is not valid hex", i));
        vector<uint8_t> key = ParseHex(keyHex);
        if (key.size() != DILITHIUM_PUBKEY_SIZE)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Key %u has invalid size %u (expected %u)",
                    i, key.size(), DILITHIUM_PUBKEY_SIZE));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("status", "not_yet_implemented");
    result.pushKV("new_threshold", (int)newThreshold);
    result.pushKV("new_key_count", (int)keyArray.size());
    result.pushKV("scheme", strprintf("%u-of-%u", newThreshold, keyArray.size()));
    result.pushKV("opcode_tag", "0x04");
    result.pushKV("witness_version", 5);
    result.pushKV("note", "Key rotation transaction construction requires wallet integration.");

    return result;
}

// =========================================================================
// usdsoqgenkeys — Generate a Dilithium ML-DSA-44 keypair for authority use
// =========================================================================
static UniValue usdsoqgenkeys(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "usdsoqgenkeys\n"
            "\nGenerate a fresh Dilithium ML-DSA-44 keypair for USDSOQ authority use.\n"
            "The private key is returned for OFFLINE storage — never expose it on-chain.\n"
            "Use the public key with usdsoqsetauthority to initialize the authority.\n"
            "\nResult:\n"
            "{\n"
            "  \"pubkey\": \"xxxx\",      (string) Hex-encoded 1312-byte ML-DSA-44 public key\n"
            "  \"privkey\": \"xxxx\",     (string) Hex-encoded 2560-byte ML-DSA-44 private key\n"
            "  \"algorithm\": \"xxxx\",   (string) Algorithm identifier\n"
            "  \"pubkey_size\": n,      (numeric) Public key size in bytes\n"
            "  \"privkey_size\": n      (numeric) Private key size in bytes\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("usdsoqgenkeys", "") +
            HelpExampleRpc("usdsoqgenkeys", ""));

    uint8_t pk[1312];
    uint8_t sk[2560];

    if (pqcrystals_dilithium2_ref_keypair(pk, sk) != 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Dilithium keypair generation failed");

    UniValue result(UniValue::VOBJ);
    result.pushKV("pubkey", HexStr(pk, pk + 1312));
    result.pushKV("privkey", HexStr(sk, sk + 2560));
    result.pushKV("algorithm", "ML-DSA-44 (FIPS 204)");
    result.pushKV("pubkey_size", 1312);
    result.pushKV("privkey_size", 2560);
    result.pushKV("warning", "Store the private key securely offline. Never transmit it on-chain.");

    return result;
}

// =========================================================================
// usdsoqsetauthority — Initialize authority key set (stagenet/regtest only)
// =========================================================================
static UniValue usdsoqsetauthority(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "usdsoqsetauthority threshold [\"pubkey\",...]\n"
            "\nInitialize the USDSOQ authority key set at runtime.\n"
            "Only available on stagenet and regtest (not mainnet).\n"
            "This sets the M-of-N Dilithium multisig that controls MINT/BURN/FREEZE.\n"
            "\nArguments:\n"
            "1. threshold     (numeric, required) Minimum signatures required (M)\n"
            "2. pubkeys       (array, required)   Array of hex-encoded ML-DSA-44 public keys\n"
            "\nResult:\n"
            "{\n"
            "  \"success\": true|false,\n"
            "  \"scheme\": \"M-of-N\",\n"
            "  \"threshold\": n,\n"
            "  \"key_count\": n\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("usdsoqsetauthority", "2 '[\"<hex_pubkey_1>\", \"<hex_pubkey_2>\", \"<hex_pubkey_3>\"]'") +
            HelpExampleRpc("usdsoqsetauthority", "2, [\"<hex_pubkey_1>\", \"<hex_pubkey_2>\", \"<hex_pubkey_3>\"]"));

    // SECURITY: Only allow on non-mainnet chains
    const CChainParams& chainparams = Params();
    std::string networkId = chainparams.NetworkIDString();
    if (networkId == "main")
        throw JSONRPCError(RPC_MISC_ERROR,
            "usdsoqsetauthority is not available on mainnet. "
            "Mainnet authority is configured via chainparams and can only be "
            "changed via OP_USDSOQ_ROTATE_AUTHORITY transactions.");

    // SECURITY: Prevent re-initialization (require rotation instead)
    if (g_usdsoq_authority.IsInitialized())
        throw JSONRPCError(RPC_MISC_ERROR,
            "Authority is already initialized. Use usdsoqrotatekeys to change the key set.");

    uint32_t threshold = request.params[0].get_int();
    const UniValue& keyArray = request.params[1].get_array();

    if (keyArray.size() == 0 || keyArray.size() > USDSOQ_MAX_AUTHORITY_KEYS)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Key count must be 1-%u", USDSOQ_MAX_AUTHORITY_KEYS));

    if (threshold < USDSOQ_MIN_THRESHOLD)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Threshold must be at least %u", USDSOQ_MIN_THRESHOLD));

    if (threshold > keyArray.size())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Threshold cannot exceed key count");

    std::vector<std::vector<uint8_t>> keys;
    for (unsigned int i = 0; i < keyArray.size(); i++) {
        string keyHex = keyArray[i].get_str();
        if (!IsHex(keyHex))
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Key %u is not valid hex", i));
        vector<uint8_t> key = ParseHex(keyHex);
        if (key.size() != DILITHIUM_PUBKEY_SIZE)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Key %u has invalid size %u (expected %u)",
                    i, key.size(), DILITHIUM_PUBKEY_SIZE));
        keys.push_back(key);
    }

    LOCK(cs_main);
    bool success = g_usdsoq_authority.Initialize(keys, threshold);

    UniValue result(UniValue::VOBJ);
    result.pushKV("success", success);
    if (success) {
        // Persist authority to LevelDB so it survives daemon restarts
        if (pcoinsdbview) {
            pcoinsdbview->WriteUSDSOQAuthority(g_usdsoq_authority);
            LogPrintf("USDSOQ: Authority persisted to chainstate DB\n");
        }
        result.pushKV("scheme", strprintf("%u-of-%u", threshold, keys.size()));
        result.pushKV("threshold", (int)threshold);
        result.pushKV("key_count", (int)keys.size());
        LogPrintf("USDSOQ: Authority set via RPC: %u-of-%u Dilithium multisig\n",
                  threshold, keys.size());
    } else {
        result.pushKV("error", "Authority initialization failed — check key sizes and threshold");
    }

    return result;
}

// =========================================================================
// RPC Command Registration
// =========================================================================
static const CRPCCommand commands[] =
{
    //  category    name                    actor (function)          okSafe argNames
    //  ----------  ----------------------  ------------------------  ------ --------
    { "usdsoq", "getusdsoqstatus",         &getusdsoqstatus,         true,  {} },
    { "usdsoq", "getusdsoqauthority",      &getusdsoqauthority,      true,  {} },
    { "usdsoq", "verifyusdsoqauthority",   &verifyusdsoqauthority,   true,  {"message", "signatures"} },
    { "usdsoq", "usdsoqmint",             &usdsoqmint,              false, {"amount", "destination"} },
    { "usdsoq", "usdsoqburn",             &usdsoqburn,              false, {"amount"} },
    { "usdsoq", "usdsoqfreeze",           &usdsoqfreeze,            false, {"txid", "vout"} },
    { "usdsoq", "usdsoqrotatekeys",       &usdsoqrotatekeys,        false, {"threshold", "pubkeys"} },
    { "usdsoq", "usdsoqgenkeys",          &usdsoqgenkeys,           true,  {} },
    { "usdsoq", "usdsoqsetauthority",     &usdsoqsetauthority,      false, {"threshold", "pubkeys"} },
};

void RegisterUSDSOQRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int i = 0; i < ARRAYLEN(commands); i++)
        tableRPC.appendCommand(commands[i].name, &commands[i]);
}
