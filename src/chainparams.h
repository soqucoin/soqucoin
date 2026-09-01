// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMS_H
#define BITCOIN_CHAINPARAMS_H

#include "chainparamsbase.h"
#include "consensus/params.h"
#include "primitives/block.h"
#include "protocol.h"

#include <vector>

struct CDNSSeedData {
    std::string name, host;
    bool supportsServiceBitsFiltering;
    CDNSSeedData(const std::string& strName, const std::string& strHost, bool supportsServiceBitsFilteringIn = false) : name(strName), host(strHost), supportsServiceBitsFiltering(supportsServiceBitsFilteringIn) {}
};

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

typedef std::map<int, uint256> MapCheckpoints;

struct CCheckpointData {
    MapCheckpoints mapCheckpoints;
};

struct ChainTxData {
    int64_t nTime;
    int64_t nTxCount;
    double dTxRate;
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CChainParams
{
public:
    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        MAX_BASE58_TYPES
    };

    const Consensus::Params& GetConsensus(uint32_t nTargetHeight) const
    {
        return *(pConsensusRoot->GetConsensus(nTargetHeight));
    }

    const CMessageHeader::MessageStartChars& MessageStart() const { return pchMessageStart; }
    int GetDefaultPort() const { return nDefaultPort; }

    const CBlock& GenesisBlock() const { return genesis; }
    /** Make miner wait to have peers to avoid wasting work */
    bool MiningRequiresPeers() const { return fMiningRequiresPeers; }
    /** Default value for -checkmempool and -checkblockindex argument */
    bool DefaultConsistencyChecks() const { return fDefaultConsistencyChecks; }
    /** Policy: Filter transactions that do not match well-defined patterns */
    bool RequireStandard() const { return fRequireStandard; }
    uint64_t PruneAfterHeight() const { return nPruneAfterHeight; }
    /** Make miner stop after a block is found. In RPC, don't return until nGenProcLimit blocks are generated */
    bool MineBlocksOnDemand() const { return fMineBlocksOnDemand; }
    /** Return the BIP70 network string (main, test or regtest) */
    std::string NetworkIDString() const { return strNetworkID; }
    const std::vector<CDNSSeedData>& DNSSeeds() const { return vSeeds; }
    const std::vector<unsigned char>& Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const std::vector<SeedSpec6>& FixedSeeds() const { return vFixedSeeds; }
    const CCheckpointData& Checkpoints() const { return checkpointData; }
    const ChainTxData& TxData() const { return chainTxData; }
    const std::string& Bech32HRP() const { return bech32HRP; }
    /** Genesis-migration committed allocation outputs, in committed order — the
     *  preimage of Consensus::Params::hashMigrationOutputs. Used only by the block
     *  template builder (miner.cpp); validation consults the hash alone. Empty on
     *  every network until the genesis ceremony compiles the ceremony vector in
     *  beside the constants (regtest injects it via -migrationoutputs). */
    const std::vector<CTxOut>& MigrationOutputs() const { return vMigrationOutputs; }

protected:
    CChainParams() {}

    Consensus::Params consensus;
    Consensus::Params* pConsensusRoot; // Binary search tree root
    CMessageHeader::MessageStartChars pchMessageStart;
    int nDefaultPort;
    uint64_t nPruneAfterHeight;
    std::vector<CDNSSeedData> vSeeds;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    std::string strNetworkID;
    std::string bech32HRP;
    CBlock genesis;
    std::vector<SeedSpec6> vFixedSeeds;
    bool fMiningRequiresPeers;
    bool fDefaultConsistencyChecks;
    bool fRequireStandard;
    bool fMineBlocksOnDemand;
    CCheckpointData checkpointData;
    ChainTxData chainTxData;
    std::vector<CTxOut> vMigrationOutputs;
};

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CChainParams& Params();

/**
 * @returns CChainParams for the given BIP70 chain name.
 */
CChainParams& Params(const std::string& chain);

/**
 * Sets the params returned by Params() to those for the given BIP70 chain name.
 * @throws std::runtime_error when the chain is not supported.
 */
void SelectParams(const std::string& chain);

/**
 * Allows modifying the BIP9 regtest parameters.
 */
void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout);

/**
 * Allows overriding a regtest deployment's flag-day activation height.
 *
 * ⚠️ UpdateRegtestBIP9Parameters above is a NO-OP for any deployment that has an
 * nActivationHeight set: DeploymentActiveAtHeight() consults nActivationHeight
 * ONLY, and never nStartTime/nTimeout (consensus/params.h, bead p96 Option D).
 * Every Soqucoin deployment is height-gated, so the BIP9 lever cannot activate
 * any of them — which left the SoquObscura-gated reject paths untestable, and
 * therefore untested. That is precisely the gap that let SOQ-ARCH-004 sit dead
 * through a 597/597 green suite (beads don9, n1vf, r0vn).
 *
 * Regtest only, and it mutates the regtest singleton, so a test that flips a
 * deployment MUST restore the previous value (BIP9Deployment::NOT_SCHEDULED for
 * a dormant one) before it returns.
 */
void UpdateRegtestActivationHeight(Consensus::DeploymentPos d, int nActivationHeight);

/**
 * Allows overriding the regtest finality horizon (Consensus::nMaxReorgDepth)
 * for functional tests. Regtest only.
 */
void UpdateRegtestMaxReorgDepth(int nMaxReorgDepth);

/**
 * Arms the genesis-migration allocation rule on regtest
 * (DL-GENESIS-MIGRATION-IMPLEMENTATION §A1). Sets the three consensus constants
 * exactly as given — hash, total and height are taken independently so tests can
 * arm deliberately inconsistent values (tamper case 10) — and installs vOutputs
 * as the miner's committed vector. Regtest only; it mutates the regtest
 * singleton, so a test that arms the rule MUST disarm it (null hash, 0, 0, {})
 * before it returns.
 */
void UpdateRegtestMigrationParams(const uint256& hashOutputs, CAmount nTotal, int nHeight,
                                  const std::vector<CTxOut>& vOutputs);

/** Test-only (regtest): set the PAT mandatory-commitment height
 *  (doc/PAT_BLOCK_ATTESTATION.md §7). 0 restores the never-mandatory default. */
void UpdateRegtestPatCommitmentMandatoryHeight(int nHeight);

#endif // BITCOIN_CHAINPARAMS_H
