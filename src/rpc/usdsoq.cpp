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
#include "script/interpreter.h"
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
        // SOQ-AUD2-002 D1: Read from global supply counter (persisted to/from LevelDB)
        supply.pushKV("total_minted", ValueFromAmount(g_usdsoq_supply.TotalMinted()));
        supply.pushKV("total_burned", ValueFromAmount(g_usdsoq_supply.TotalBurned()));
        supply.pushKV("outstanding", ValueFromAmount(g_usdsoq_supply.Outstanding()));
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

// Build the unsigned registry-format freeze/unfreeze tx. NO inputs — usdsoqsigntx adds the
// authority input + OP_5 authority output and signs (opcode_tag=3). The target outpoint is
// NAMED in the OP_RETURN as DATA (it is NOT spent and stays unspent); ConnectBlock adds/removes
// it from DB_USDSOQ_FROZEN. Layout matches consensus/usdsoq.cpp ParseUSDSOQFreezeOp exactly:
//   OP_RETURN <"FREEZE"> <[op:1][txid:32 internal][vout:4 LE]>   (payload = FREEZE_OP_PAYLOAD_LEN)
static CMutableTransaction MakeRegistryFreezeTx(uint8_t freezeOp, const uint256& txid, uint32_t vout)
{
    std::vector<unsigned char> payload(FREEZE_OP_PAYLOAD_LEN);
    payload[0] = freezeOp;
    for (int i = 0; i < 32; ++i) payload[1 + i] = *(txid.begin() + i);  // internal byte order (matches parser memcpy)
    payload[33] = (unsigned char)(vout & 0xFF);
    payload[34] = (unsigned char)((vout >> 8) & 0xFF);
    payload[35] = (unsigned char)((vout >> 16) & 0xFF);
    payload[36] = (unsigned char)((vout >> 24) & 0xFF);

    CScript opret;
    opret << OP_RETURN
          << std::vector<unsigned char>{'F','R','E','E','Z','E'}
          << payload;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vout.push_back(CTxOut(0, opret));  // value-0 OP_RETURN, no inputs
    return mtx;
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

    uint256 txid = ParseHashV(request.params[0], "txid");
    int vout = request.params[1].get_int();
    if (vout < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be non-negative");

    // Registry format: no inputs; one OP_RETURN naming the target (NOT spent). usdsoqsigntx
    // (opcode_tag=3) adds the authority input + OP_5 output and signs; ConnectBlock then adds
    // the target to DB_USDSOQ_FROZEN (ParseUSDSOQFreezeOp). The target UTXO stays unspent.
    CMutableTransaction mtx = MakeRegistryFreezeTx(FREEZE_OP_FREEZE, txid, (uint32_t)vout);

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(mtx));
    result.pushKV("target_txid", txid.GetHex());
    result.pushKV("target_vout", vout);
    result.pushKV("op", "freeze");
    result.pushKV("opcode_tag", "0x03 (OP_USDSOQ_FREEZE)");
    result.pushKV("status", "unsigned");
    result.pushKV("genius_act", "§4(a)(2) compliance: stablecoin issuer freeze capability");
    result.pushKV("next_step", "Sign with usdsoqsigntx opcode_tag=3, then broadcast via sendrawtransaction");

    return result;
}

// =========================================================================
// usdsoqunfreeze — Construct an UNFREEZE authority transaction (unsigned)
// Reverses a freeze: removes the target outpoint from DB_USDSOQ_FROZEN so it can be spent
// again. Same registry format as freeze, op = FREEZE_OP_UNFREEZE; signed with opcode_tag=3
// (the op-flag byte, not the witness tag, distinguishes freeze from unfreeze).
// =========================================================================
static UniValue usdsoqunfreeze(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "usdsoqunfreeze \"txid\" vout\n"
            "\nConstruct an unsigned USDSOQ UNFREEZE transaction for a specific UTXO.\n"
            "Reverses a prior freeze (removes the outpoint from the frozen set so it can be spent).\n"
            "Must be signed with M-of-N Dilithium authority keys via usdsoqsigntx (opcode_tag=3).\n"
            "GENIUS Act §4(a)(2) compliance: issuer freeze/unfreeze capability.\n"
            "\nArguments:\n"
            "1. \"txid\"   (string, required) Transaction ID of the UTXO to unfreeze\n"
            "2. vout      (numeric, required) Output index of the UTXO to unfreeze\n"
            "\nExamples:\n" +
            HelpExampleCli("usdsoqunfreeze", "\"txid\" 0") +
            HelpExampleRpc("usdsoqunfreeze", "\"txid\", 0"));

    LOCK(cs_main);

    const Consensus::Params& consensus = Params().GetConsensus(chainActive.Height());
    ThresholdState state = VersionBitsState(chainActive.Tip(),
        consensus, Consensus::DEPLOYMENT_USDSOQ, versionbitscache);
    if (state != THRESHOLD_ACTIVE) {
        throw JSONRPCError(RPC_MISC_ERROR,
            "USDSOQ deployment is not active. Unfreeze operations are not available.");
    }

    uint256 txid = ParseHashV(request.params[0], "txid");
    int vout = request.params[1].get_int();
    if (vout < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be non-negative");

    CMutableTransaction mtx = MakeRegistryFreezeTx(FREEZE_OP_UNFREEZE, txid, (uint32_t)vout);

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(mtx));
    result.pushKV("target_txid", txid.GetHex());
    result.pushKV("target_vout", vout);
    result.pushKV("op", "unfreeze");
    result.pushKV("opcode_tag", "0x03 (OP_USDSOQ_FREEZE; op=unfreeze)");
    result.pushKV("status", "unsigned");
    result.pushKV("next_step", "Sign with usdsoqsigntx opcode_tag=3, then broadcast via sendrawtransaction");

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
// usdsoqsigntx — Sign a USDSOQ authority transaction with Dilithium keys
// =========================================================================
// SOQ-I005: This RPC bridges the gap between unsigned authority TXs
// (produced by usdsoqmint/burn/freeze) and broadcast via sendrawtransaction.
//
// It performs the following:
//   1. Decodes the unsigned TX
//   2. Adds the authority input (spends the tracked authority UTXO)
//   3. Adds a fee input (SOQ for miner fees)
//   4. Adds the OP_5 <keyhash> authority output (continues the UTXO chain)
//   5. Computes BIP143 sighash for the authority input
//   6. Signs with each provided Dilithium private key
//   7. Constructs the v5 witness stack: [tag][payload][sig0..sigM][authority_set]
//   8. Returns the fully signed TX hex
//
// SECURITY: Private keys are provided as RPC parameters and are NEVER stored.
// This RPC is intended for offline/air-gapped signing environments.
static UniValue usdsoqsigntx(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4)
        throw runtime_error(
            "usdsoqsigntx \"hextx\" opcode_tag [\"privkey1\",\"privkey2\",...] ( \"fee_outpoint\" )\n"
            "\nSign a USDSOQ authority transaction with Dilithium private keys.\n"
            "Adds the authority input, fee input, OP_5 authority output, and\n"
            "M-of-N Dilithium signatures to an unsigned TX produced by\n"
            "usdsoqmint, usdsoqburn, or usdsoqfreeze.\n"
            "\nArguments:\n"
            "1. \"hextx\"        (string, required) Unsigned raw transaction hex from usdsoqmint/burn/freeze\n"
            "2. opcode_tag      (numeric, required) Operation tag: 1=MINT, 2=BURN, 3=FREEZE, 4=ROTATE\n"
            "3. \"privkeys\"     (array, required) Array of hex-encoded Dilithium ML-DSA-44 private keys (2560 bytes each)\n"
            "4. \"fee_outpoint\" (string, optional) Fee input as \"txid:vout\" (SOQ UTXO for miner fees).\n"
            "                    If omitted, a dummy zero-value fee input is used (for regtest/stagenet).\n"
            "\nResult:\n"
            "{\n"
            "  \"hex\": \"xxxx\",          (string) Signed raw transaction hex (ready for sendrawtransaction)\n"
            "  \"txid\": \"xxxx\",         (string) Transaction ID\n"
            "  \"authority_input\": n,    (numeric) Input index carrying the authority witness\n"
            "  \"authority_output\": n,   (numeric) Output index of the new authority UTXO\n"
            "  \"signatures\": n,         (numeric) Number of signatures applied\n"
            "  \"sighash\": \"xxxx\",      (string) BIP143 sighash that was signed (hex)\n"
            "  \"status\": \"signed\"\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("usdsoqsigntx",
                "\"<unsigned_hex>\" 1 '[\"<privkey1_hex>\",\"<privkey2_hex>\"]' \"<txid>:0\"") +
            HelpExampleRpc("usdsoqsigntx",
                "\"<unsigned_hex>\", 1, [\"<privkey1_hex>\",\"<privkey2_hex>\"], \"<txid>:0\""));

    LOCK(cs_main);

    // Check deployment
    const Consensus::Params& consensus = Params().GetConsensus(chainActive.Height());
    ThresholdState deployState = VersionBitsState(chainActive.Tip(),
        consensus, Consensus::DEPLOYMENT_USDSOQ, versionbitscache);
    if (deployState != THRESHOLD_ACTIVE)
        throw JSONRPCError(RPC_MISC_ERROR,
            "USDSOQ deployment is not active.");

    if (!g_usdsoq_authority.IsInitialized())
        throw JSONRPCError(RPC_MISC_ERROR,
            "USDSOQ authority is not initialized. Run usdsoqsetauthority first.");

    // --- Parse arguments ---

    // 1. Decode the unsigned TX
    // fTryNoWitness=true: unsigned TXs have 0 inputs, so bytes 00 01
    // (vin_count=0, vout_count=1) are misinterpreted as BIP144 segwit
    // marker+flag if we only try witness deserialization.
    string hexTx = request.params[0].get_str();
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hexTx, true))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    // 2. Opcode tag
    int opcodeTag = request.params[1].get_int();
    if (opcodeTag < 1 || opcodeTag > 4)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "opcode_tag must be 1 (MINT), 2 (BURN), 3 (FREEZE), or 4 (ROTATE)");

    // 3. Parse private keys
    const UniValue& keyArray = request.params[2].get_array();
    if (keyArray.size() == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "At least one private key is required");

    vector<vector<uint8_t>> privkeys;
    for (unsigned int i = 0; i < keyArray.size(); i++) {
        string keyHex = keyArray[i].get_str();
        if (!IsHex(keyHex))
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Private key %u is not valid hex", i));
        vector<uint8_t> sk = ParseHex(keyHex);
        if (sk.size() != pqcrystals_dilithium2_SECRETKEYBYTES)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Private key %u has invalid size %u (expected %u)",
                    i, sk.size(), pqcrystals_dilithium2_SECRETKEYBYTES));
        privkeys.push_back(sk);
    }

    // 4. Optional fee outpoint
    COutPoint feeOutpoint;
    bool hasFeeInput = false;
    if (request.params.size() >= 4 && !request.params[3].isNull()) {
        string feeStr = request.params[3].get_str();
        // Parse "txid:vout" format
        size_t colonPos = feeStr.find(':');
        if (colonPos == string::npos)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "fee_outpoint must be in \"txid:vout\" format");
        string feeTxid = feeStr.substr(0, colonPos);
        int feeVout = atoi(feeStr.substr(colonPos + 1).c_str());
        if (!IsHex(feeTxid) || feeTxid.size() != 64)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Invalid txid in fee_outpoint");
        feeOutpoint = COutPoint(uint256S(feeTxid), feeVout);
        hasFeeInput = true;
    }

    // --- Construct the complete authority TX ---

    // The authority input MUST be the first input (index 0).
    // This spends the tracked authority UTXO and carries the witness.

    // Build the authority output scriptPubKey: OP_5 <SHA256(authority_keys)>
    uint256 authKeyHash = ComputeAuthorityKeyHash(g_usdsoq_authority.GetKeys());
    CScript authScript;
    authScript << OP_5;
    authScript << std::vector<unsigned char>(authKeyHash.begin(), authKeyHash.end());

    // Save existing outputs from the unsigned TX
    vector<CTxOut> existingOutputs = mtx.vout;

    // Rebuild the TX with proper structure:
    //   Input 0: authority input (spends current authority UTXO)
    //   Input 1: fee input (SOQ for miner fees) — if provided
    //   Output 0: authority output (OP_5 <keyhash>) — continues the chain
    //   Output 1+: original outputs from unsigned TX (mint dest, burn OP_RETURN, etc.)
    mtx.vin.clear();
    mtx.vout.clear();

    // Authority input: spend the tracked authority UTXO
    COutPoint authOutpoint = g_usdsoq_authority_outpoint;
    if (authOutpoint.IsNull()) {
        // No tracked outpoint yet (pre-bootstrap). Use the fee outpoint
        // as the authority input carrier. The ConnectBlock bootstrap
        // fallback accepts any input as the authority carrier when
        // g_usdsoq_authority_outpoint is null.
        if (!hasFeeInput)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Bootstrap mode: fee_outpoint is required for the first authority TX "
                "(no existing authority UTXO to spend). Provide a SOQ UTXO as fee_outpoint.");
        authOutpoint = feeOutpoint;
        hasFeeInput = false;  // Don't add it again as a separate input
        LogPrintf("USDSOQ: usdsoqsigntx: No tracked authority outpoint — "
                  "using fee outpoint %s as bootstrap authority input\n",
                  authOutpoint.ToString());
    }
    CTxIn authInput(authOutpoint);
    authInput.nSequence = 0xFFFFFFFF;
    mtx.vin.push_back(authInput);

    // Fee input (if provided)
    if (hasFeeInput) {
        CTxIn feeInput(feeOutpoint);
        feeInput.nSequence = 0xFFFFFFFF;
        mtx.vin.push_back(feeInput);
    }

    // Authority output (index 0): continues the UTXO chain
    CTxOut authOutput(CAmount(0), authScript);
    mtx.vout.push_back(authOutput);

    // Original outputs (index 1+)
    for (const auto& out : existingOutputs) {
        mtx.vout.push_back(out);
    }

    // --- Compute BIP143 sighash for the authority input ---
    CTransaction txConst(mtx);
    PrecomputedTransactionData txdata(txConst);

    // SECURITY: SIGHASH_ALL — binds the signature to ALL inputs and outputs.
    // The authority input (index 0) scriptPubKey is the OP_5 <keyhash> script.
    uint256 sighash = SignatureHash(
        authScript, txConst, 0, SIGHASH_ALL,
        CAmount(0),  // Authority UTXOs are 0-value
        SIGVERSION_WITNESS_V0, &txdata);

    // --- Sign with each Dilithium private key ---
    vector<vector<uint8_t>> signatures;
    for (size_t i = 0; i < privkeys.size(); i++) {
        uint8_t sig[pqcrystals_dilithium2_BYTES];
        size_t siglen = 0;

        int ret = pqcrystals_dilithium2_ref_signature(
            sig, &siglen,
            sighash.begin(), 32,   // Message = sighash (32 bytes)
            nullptr, 0,             // Empty FIPS 204 context string
            privkeys[i].data());

        if (ret != 0)
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                strprintf("Dilithium signing failed for key %u (error %d)", i, ret));

        if (siglen != DILITHIUM_SIG_SIZE)
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                strprintf("Unexpected signature size %u (expected %u)", siglen, DILITHIUM_SIG_SIZE));

        signatures.push_back(vector<uint8_t>(sig, sig + siglen));
    }

    // --- Construct the v5 witness stack ---
    // Layout: [tag][payload][sig0][sig1]...[sigM][authority_set]
    //
    // tag:           1-byte opcode tag (0x01=MINT, 0x02=BURN, 0x03=FREEZE, 0x04=ROTATE)
    // payload:       operation-specific data (amount for MINT/BURN, outpoint for FREEZE)
    // sig0..sigM:    M Dilithium signatures (2420 bytes each)
    // authority_set: serialized authority key set for validation

    CScriptWitness& witness = mtx.vin[0].scriptWitness;
    witness.stack.clear();

    // Item 0: opcode tag
    witness.stack.push_back(vector<uint8_t>{(uint8_t)opcodeTag});

    // Item 1: payload (operation-specific)
    // For signing purposes, we encode the sighash as the payload
    // (the actual opcode handler in EvalScript interprets this)
    vector<uint8_t> payload(sighash.begin(), sighash.end());
    witness.stack.push_back(payload);

    // Items 2..M+1: Dilithium signatures
    for (const auto& sig : signatures) {
        witness.stack.push_back(sig);
    }

    // Item M+2: authority key set (serialized for verifier reference)
    // This allows the verifier to reconstruct which keys to check against.
    // Format: [threshold (4 bytes LE)][N (4 bytes LE)][key0..keyN]
    vector<uint8_t> authSet;
    uint32_t threshold = g_usdsoq_authority.GetThreshold();
    uint32_t keyCount = (uint32_t)g_usdsoq_authority.GetKeyCount();
    authSet.push_back(threshold & 0xFF);
    authSet.push_back((threshold >> 8) & 0xFF);
    authSet.push_back((threshold >> 16) & 0xFF);
    authSet.push_back((threshold >> 24) & 0xFF);
    authSet.push_back(keyCount & 0xFF);
    authSet.push_back((keyCount >> 8) & 0xFF);
    authSet.push_back((keyCount >> 16) & 0xFF);
    authSet.push_back((keyCount >> 24) & 0xFF);
    for (const auto& key : g_usdsoq_authority.GetKeys()) {
        authSet.insert(authSet.end(), key.begin(), key.end());
    }
    witness.stack.push_back(authSet);

    // --- Build result ---
    CTransaction signedTx(mtx);
    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(signedTx));
    result.pushKV("txid", signedTx.GetHash().GetHex());
    result.pushKV("authority_input", 0);
    result.pushKV("authority_output", 0);
    result.pushKV("fee_input", hasFeeInput ? 1 : -1);
    result.pushKV("signatures", (int)signatures.size());
    result.pushKV("sighash", sighash.GetHex());
    result.pushKV("sighash_type", "SIGHASH_ALL");
    result.pushKV("status", "signed");
    result.pushKV("next_step", "Broadcast via: soqucoin-cli sendrawtransaction \"" +
        EncodeHexTx(signedTx).substr(0, 32) + "...\"");

    LogPrintf("USDSOQ: usdsoqsigntx: TX %s signed with %u Dilithium signatures "
              "(tag=%d, sighash=%s)\n",
        signedTx.GetHash().ToString(), signatures.size(), opcodeTag,
        sighash.GetHex());

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
    { "usdsoq", "usdsoqunfreeze",         &usdsoqunfreeze,          false, {"txid", "vout"} },
    { "usdsoq", "usdsoqrotatekeys",       &usdsoqrotatekeys,        false, {"threshold", "pubkeys"} },
    { "usdsoq", "usdsoqgenkeys",          &usdsoqgenkeys,           true,  {} },
    { "usdsoq", "usdsoqsetauthority",     &usdsoqsetauthority,      false, {"threshold", "pubkeys"} },
    { "usdsoq", "usdsoqsigntx",           &usdsoqsigntx,            false, {"hextx", "opcode_tag", "privkeys", "fee_outpoint"} },
};

void RegisterUSDSOQRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int i = 0; i < ARRAYLEN(commands); i++)
        tableRPC.appendCommand(commands[i].name, &commands[i]);
}
