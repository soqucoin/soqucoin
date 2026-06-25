// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021-2022 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include "uint256.h"
#include <array>
#include <limits>
#include <map>
#include <string>

namespace Consensus
{

enum DeploymentPos {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV,    // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.
    DEPLOYMENT_CHECKPATAGG,
    DEPLOYMENT_LATTICEFOLD,
    DEPLOYMENT_LATTICEBP,
    DEPLOYMENT_USDSOQ,     // SOQ-AUD2-002: USDSOQ stablecoin (bit 6)
    DEPLOYMENT_CTV,        // BIP 119: OP_CHECKTEMPLATEVERIFY (bit 7) — vaults, covenants
    DEPLOYMENT_APO,        // BIP 118: SIGHASH_ANYPREVOUT (bit 8) — eltoo Lightning
    DEPLOYMENT_CSFS,       // BIP 348: OP_CHECKSIGFROMSTACK (bit 9) — oracle contracts, bridge attestation
    DEPLOYMENT_P2WSH_DILITHIUM, // Witness v6: P2WSH with Dilithium (bit 10) — covenant script execution, L2SOQ Lightning
    DEPLOYMENT_UTXO_COST,       // SOQ-ARCH-003: Consensus-enforced minimum UTXO value (bit 11) — Cardano-style utxoCostPerByte
    DEPLOYMENT_DILITHIUM_KEYHASH, // OP_CHECKDILITHIUMKEYHASH (bit 12) — key-committed Dilithium sig verify, eLTOO 2-of-2 multisig
    DEPLOYMENT_V6_CONTROLFLOW, // DL-V6-CONTROLFLOW-RESTORE (bit 13) — IF/CLTV/CSV/DROP/SHA256/EQUAL in v6 EvalScript (eLTOO ratchet, HTLC)
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;

    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();
    static constexpr int64_t ALWAYS_ACTIVE = -1;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Used to check majorities for block version upgrade */
    int nMajorityEnforceBlockUpgrade;
    int nMajorityRejectBlockOutdated;
    int nMajorityWindow;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    uint32_t nCoinbaseMaturity;
    /**
     * Finality horizon (anti-deep-reorg). Reject any block that builds on a
     * fork more than this many blocks below the active tip, i.e. refuse to
     * reorganize deeper than nMaxReorgDepth. 0 = disabled.
     *
     * Rationale (Analysis [A], 2026-06-22): SOQ is a small merge-mined chain
     * whose committed scrypt hashrate is a rounding error against the rentable
     * scrypt market, and renting a 51% majority is ~free because the same
     * hashrate earns LTC+DOGE. PoW weight therefore cannot secure the chain
     * (the CoiledCoin failure mode). A bounded reorg horizon converts an
     * unlimited-time cheap attack into a bounded-window one and makes deeply
     * buried history final regardless of attacker hashrate. Must exceed any
     * realistic natural reorg depth (a few blocks) by a wide margin.
     */
    int nMaxReorgDepth = 0;
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }

    /** Soqucoin-specific parameters */
    bool fDigishieldDifficultyCalculation;
    bool fPowAllowDigishieldMinDifficultyBlocks; // Allow minimum difficulty blocks where a retarget would normally occur
    bool fSimplifiedRewards;                     // Use block height derived rewards rather than previous block hash derived

    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;
    int32_t dilithiumOnlyHeight;
    int32_t nLatticeFoldActivationHeight;

    /** Auxpow parameters */
    int32_t nAuxpowChainId;
    bool fStrictChainId;
    bool fAllowLegacyBlocks;
    int32_t nAuxpowStartHeight = 0;  // Height at which AuxPoW blocks become valid (mainnet: 0 = from genesis)

    /** Height-aware consensus parameters */
    uint32_t nHeightEffective;       // When these parameters come into use
    struct Params* pLeft = nullptr;  // Left hand branch
    struct Params* pRight = nullptr; // Right hand branch
    const Consensus::Params* GetConsensus(uint32_t nTargetHeight) const;

    /** USDSOQ authority key set (SOQ-AUD2-002, D4)
     *  Initial M-of-N Dilithium public keys for MINT/BURN/FREEZE/ROTATE.
     *  Loaded from chainparams on BIP9 activation. Keys are hex-encoded
     *  1312-byte ML-DSA-44 public keys. Can be rotated on-chain via
     *  OP_USDSOQ_ROTATE_AUTHORITY. Empty = no authority (mainnet at genesis). */
    std::vector<std::string> usdsoqAuthorityKeys;
    uint32_t usdsoqAuthorityThreshold = 0;

    /** SOQ-I005-STAGENET: USDSOQ authority signature enforcement height.
     *  Before this height, USDSOQ authority TXs (bootstrap or chain) are
     *  accepted WITHOUT authority signature verification. This exempts
     *  pre-authority test mints on stagenet (blocks 0–37200).
     *
     *  MAINNET: Set to 0 — authority signatures enforced from BIP9 activation.
     *  No unsigned USDSOQ TX can exist before BIP9 activates USDSOQ, so the
     *  enforcement height is irrelevant (there are no blocks to exempt).
     *
     *  STAGENET: Set to 37201 — blocks 0-37200 exempt (pre-authority test mints).
     *  Authority signature verification required from block 37201 onward.
     *
     *  See SECURITY_ISSUE_REGISTRY.md SOQ-I005-STAGENET for full rationale. */
    int32_t nUSDSOQAuthorityEnforcementHeight = 0;

    /** SOQ-I007-STAGENET: UTXO cost minimum enforcement height.
     *  Before this height, the UTXO_COST_PER_BYTE minimum is not enforced
     *  even if DEPLOYMENT_UTXO_COST is ALWAYS_ACTIVE. This exempts
     *  pre-UTXO-cost blocks on stagenet.
     *
     *  MAINNET: Set to 0 — enforced from BIP9 activation.
     *  STAGENET: Set to 37201 — blocks 0-37200 exempt. */
    int32_t nUtxoCostEnforcementHeight = 0;

    /** SOQ-H3: Lattice-BP++ privacy system consensus seed.
     *  Deterministically generates matrix A for Ring-LWE Pedersen commitments.
     *  Derived via HKDF-SHA256(genesis_hash, domain, lattice_params).
     *  "Nothing up my sleeve": genesis hash predates privacy implementation.
     *  Different per-network: mainnet, stagenet, regtest each get unique A.
     *  MUST match between soqucoind and soq-privacy-signer for proof verification. */
    std::array<uint8_t, 32> latticeBPSeed = {};
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
