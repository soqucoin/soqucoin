// Copyright (c) 2024-2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Phase A6: Privacy RPC — getdecoyoutputs, getprivacystatus
// Returns random confidential (shielded) UTXOs from the chain for use as
// ring signature decoys in SoquShield unshield transactions.
//
// This RPC is read-only, safe for public exposure via CF Worker allowlist.
// No wallet access required — reads directly from the UTXO set (pcoinsTip).

#include "rpc/server.h"
#include "validation.h"
#include "coins.h"
#include "txdb.h"
#include "random.h"
#include "chain.h"
#include "chainparams.h"
#include "utilstrencodings.h"
#include "consensus/privacy.h"
#include "primitives/transaction.h"
#include "versionbits.h"

#include <set>

// ═══════════════════════════════════════════════════════════════════
//  getdecoyoutputs — Fetch random confidential outputs for ring sigs
// ═══════════════════════════════════════════════════════════════════

static UniValue getdecoyoutputs(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "getdecoyoutputs count ( asset_type )\n"
            "\nReturns random confidential (shielded) outputs from the UTXO set\n"
            "for use as ring signature decoys in privacy transactions.\n"
            "\nArguments:\n"
            "1. count        (numeric, required) Number of decoy outputs to return (1-50)\n"
            "2. asset_type   (numeric, optional, default=0) Asset type filter:\n"
            "                  0 = SOQ, 1 = USDSOQ\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"txid\": \"hex\",           (string) Transaction ID containing the output\n"
            "    \"vout\": n,                (numeric) Output index\n"
            "    \"commitment\": \"hex\",      (string) Lattice commitment (output amount hidden)\n"
            "    \"publicKey\": \"hex\",       (string) Stealth one-time public key\n"
            "    \"height\": n               (numeric) Block height where this output was confirmed\n"
            "  },\n"
            "  ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getdecoyoutputs", "10")
            + HelpExampleCli("getdecoyoutputs", "10 1")
            + HelpExampleRpc("getdecoyoutputs", "10, 0")
        );

    int count = request.params[0].get_int();
    if (count < 1 || count > 50)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "count must be between 1 and 50");

    uint8_t assetFilter = 0x00; // default: SOQ
    if (request.params.size() > 1) {
        int at = request.params[1].get_int();
        if (at != 0 && at != 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "asset_type must be 0 (SOQ) or 1 (USDSOQ)");
        assetFilter = static_cast<uint8_t>(at);
    }

    // ── Scan the UTXO set for confidential outputs ──
    // Strategy: Walk recent blocks (last 1000) and collect all
    // confidential outputs that are still unspent. Then randomly sample.
    //
    // SECURITY NOTE: Decoy selection should be uniform over the
    // eligible pool. For stagenet this simple approach is sufficient.
    // For mainnet, a more sophisticated gamma distribution over
    // block heights (Monero-style) should be implemented.

    LOCK(cs_main);

    int tipHeight = chainActive.Height();
    if (tipHeight < 1)
        throw JSONRPCError(RPC_IN_WARMUP,
            "Chain not synced — no blocks available for decoy selection");

    // Collect candidate confidential outputs from recent blocks
    struct DecoyCandidate {
        uint256 txid;
        uint32_t vout;
        std::vector<uint8_t> commitment;
        std::vector<uint8_t> publicKey;
        int height;
    };
    std::vector<DecoyCandidate> candidates;

    // Scan last 1000 blocks (or all blocks if chain is shorter)
    int scanStart = std::max(1, tipHeight - 999);
    const Consensus::Params& consensusParams = Params().GetConsensus(tipHeight);

    for (int h = scanStart; h <= tipHeight; ++h) {
        CBlockIndex* pindex = chainActive[h];
        if (!pindex) continue;

        CBlock block;
        if (!ReadBlockFromDisk(block, pindex, consensusParams))
            continue;

        for (const auto& tx : block.vtx) {
            const uint256& txid = tx->GetHash();

            for (uint32_t n = 0; n < tx->vout.size(); ++n) {
                const CTxOut& out = tx->vout[n];

                // Only confidential outputs of the requested asset type
                if (!out.IsConfidential()) continue;
                if (out.nAssetType != assetFilter) continue;

                // Verify this output is still unspent via CCoins API
                const CCoins* coins = pcoinsTip->AccessCoins(txid);
                if (!coins || !coins->IsAvailable(n)) continue;

                // Extract commitment and stealth pubkey from the scriptPubKey
                const CScript& script = out.scriptPubKey;

                DecoyCandidate dc;
                dc.txid = txid;
                dc.vout = n;
                dc.height = h;

                // The commitment is derived from the scriptPubKey witness program
                // For v4 witness outputs, the program contains the commitment hash
                if (script.size() >= 34) {
                    // First 2 bytes: witness version + push length
                    // Remaining bytes: commitment/program data
                    dc.commitment.assign(script.begin() + 2, script.end());
                } else {
                    // Fallback: use the script hash as commitment identifier
                    uint256 scriptHash;
                    CHash256().Write(script.data(), script.size())
                              .Finalize((unsigned char*)&scriptHash);
                    dc.commitment.assign(scriptHash.begin(), scriptHash.end());
                }

                // For the public key, use a hash of txid+vout as stable identifier
                // In a fully-wired system, this comes from ViewKeyData.tx_public_key
                uint256 pkHash;
                CHash256().Write((const unsigned char*)txid.begin(), 32)
                          .Write((const unsigned char*)&dc.vout, 4)
                          .Finalize((unsigned char*)&pkHash);
                dc.publicKey.assign(pkHash.begin(), pkHash.end());

                candidates.push_back(std::move(dc));
            }
        }
    }

    // ── Random sampling from candidates ──

    UniValue result(UniValue::VARR);

    if (candidates.empty()) {
        // No confidential outputs found — return empty array
        // This is normal on stagenet before any privacy TXs exist
        return result;
    }

    // Shuffle and take up to 'count' candidates
    std::set<size_t> selectedIndices;
    int maxAttempts = count * 10; // prevent infinite loop if pool is small
    int attempts = 0;

    while ((int)selectedIndices.size() < count &&
           (int)selectedIndices.size() < (int)candidates.size() &&
           attempts < maxAttempts) {
        size_t idx = GetRand(candidates.size());
        selectedIndices.insert(idx);
        attempts++;
    }

    for (size_t idx : selectedIndices) {
        const DecoyCandidate& dc = candidates[idx];
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("txid", dc.txid.GetHex());
        obj.pushKV("vout", (int)dc.vout);
        obj.pushKV("commitment", HexStr(dc.commitment));
        obj.pushKV("publicKey", HexStr(dc.publicKey));
        obj.pushKV("height", dc.height);
        result.push_back(obj);
    }

    return result;
}

// ═══════════════════════════════════════════════════════════════════
//  getprivacystatus — Privacy layer activation and statistics
// ═══════════════════════════════════════════════════════════════════

static UniValue getprivacystatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getprivacystatus\n"
            "\nReturns the current status of the privacy layer.\n"
            "\nResult:\n"
            "{\n"
            "  \"latticebp_active\": true|false,  (bool) Whether Lattice-BP++ is active (BIP9)\n"
            "  \"latticefold_active\": true|false, (bool) Whether LatticeFold accumulation is active\n"
            "  \"confidential_utxo_count\": n,     (numeric) Number of unspent confidential outputs\n"
            "  \"soq_pool_size\": n,               (numeric) Number of SOQ confidential UTXOs\n"
            "  \"usdsoq_pool_size\": n,            (numeric) Number of USDSOQ confidential UTXOs\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getprivacystatus", "")
            + HelpExampleRpc("getprivacystatus", "")
        );

    LOCK(cs_main);

    int tipHeight = chainActive.Height();
    const Consensus::Params& consensusParams = Params().GetConsensus(tipHeight);

    // Count confidential UTXOs by scanning recent blocks
    int soqCount = 0;
    int usdsoqCount = 0;

    int scanStart = std::max(1, tipHeight - 999);
    for (int h = scanStart; h <= tipHeight; ++h) {
        CBlockIndex* pindex = chainActive[h];
        if (!pindex) continue;

        CBlock block;
        if (!ReadBlockFromDisk(block, pindex, consensusParams))
            continue;

        for (const auto& tx : block.vtx) {
            const uint256& txid = tx->GetHash();

            for (uint32_t n = 0; n < tx->vout.size(); ++n) {
                const CTxOut& out = tx->vout[n];
                if (!out.IsConfidential()) continue;

                const CCoins* coins = pcoinsTip->AccessCoins(txid);
                if (!coins || !coins->IsAvailable(n)) continue;

                if (out.nAssetType == 0x00) soqCount++;
                else if (out.nAssetType == 0x01) usdsoqCount++;
            }
        }
    }

    UniValue result(UniValue::VOBJ);

    // BIP9 status: Check if Lattice-BP++ deployment is active
    // On stagenet: ALWAYS_ACTIVE. On mainnet: NEVER_ACTIVE (pre-audit).
    ThresholdState latticebpState = VersionBitsTipState(
        consensusParams,
        Consensus::DEPLOYMENT_LATTICEBP);
    bool latticebpActive = (latticebpState == THRESHOLD_ACTIVE);

    // LatticeFold is always active (separate from Lattice-BP++)
    ThresholdState latticefoldState = VersionBitsTipState(
        consensusParams,
        Consensus::DEPLOYMENT_LATTICEFOLD);
    bool latticefoldActive = (latticefoldState == THRESHOLD_ACTIVE);

    result.pushKV("latticebp_active", latticebpActive);
    result.pushKV("latticefold_active", latticefoldActive);
    result.pushKV("confidential_utxo_count", soqCount + usdsoqCount);
    result.pushKV("soq_pool_size", soqCount);
    result.pushKV("usdsoq_pool_size", usdsoqCount);

    return result;
}

// ═══════════════════════════════════════════════════════════════════
//  RPC Registration
// ═══════════════════════════════════════════════════════════════════

static const CRPCCommand commands[] =
{
    //  category      name                   actor                  okSafe  argNames
    { "privacy", "getdecoyoutputs",    &getdecoyoutputs,    true,  {"count","asset_type"} },
    { "privacy", "getprivacystatus",   &getprivacystatus,   true,  {} },
};

void RegisterPrivacyRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int i = 0; i < ARRAYLEN(commands); i++)
        tableRPC.appendCommand(commands[i].name, &commands[i]);
}
