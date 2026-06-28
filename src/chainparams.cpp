// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022-2024 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/hmac_sha256.h"

#include <assert.h>
#include <cstring>

#include <boost/assign/list_of.hpp>


#include "chainparamsseeds.h"

/**
 * SOQ-H3: Derive Lattice-BP++ consensus seed from genesis block hash.
 *
 * Uses HKDF-SHA256 (RFC 5869) with:
 *   IKM  = genesis_block_hash (32 bytes)
 *   salt = domain separator string
 *   info = lattice parameter binding string
 *
 * This gives "nothing up my sleeve" assurance:
 *   - Genesis hash is public and predates privacy implementation
 *   - Different chains (mainnet, stagenet, regtest) get different A matrices
 *   - Lattice parameters (N, Q, K) are bound into the derivation
 *   - Version suffix allows future migration without breaking existing proofs
 */
static std::array<uint8_t, 32> ComputeLatticeBPSeed(
    const uint256& genesisHash,
    const char* domain,
    const char* info)
{
    // HKDF-Extract: PRK = HMAC-SHA256(salt=domain, IKM=genesis_hash)
    unsigned char prk[32];
    CHMAC_SHA256 extract(
        reinterpret_cast<const unsigned char*>(domain), strlen(domain));
    extract.Write(genesisHash.begin(), 32);
    extract.Finalize(prk);

    // HKDF-Expand: OKM = HMAC-SHA256(key=PRK, info || 0x01)
    // For 32-byte output, only one HMAC round is needed.
    std::array<uint8_t, 32> seed;
    CHMAC_SHA256 expand(prk, 32);
    expand.Write(
        reinterpret_cast<const unsigned char*>(info), strlen(info));
    unsigned char one = 0x01;
    expand.Write(&one, 1);
    expand.Finalize(seed.data());

    return seed;
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1386325540, nBits=0x1e0ffff0, nNonce=99943, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Nintondo";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Soqucoin Testnet3 Genesis Block - Dec 2025
 * First quantum-resistant Scrypt chain
 */
static CBlock CreateGenesisBlockTestnet3(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "First quantum-resistant Scrypt chain - Soqucoin Testnet3 Dec 2025";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Soqucoin Stagenet Genesis Block - Jan 2026
 * Mainnet rehearsal network with identical staged activation
 */
static CBlock CreateGenesisBlockStagenet(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Soqucoin Stagenet - Mainnet rehearsal network Jan 2026";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams
{
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;

public:
    CMainParams()
    {
        strNetworkID = "main";
        bech32HRP = "sq";

        // Blocks 0 - 144999 are conventional difficulty calculation
        // 47B Moderate emission (locked 2026-06-28, bead soqucoin-build-c61):
        // 250,000-block halving interval (~174d at 60s) × 4 halvings; 100K launch
        // reward + 2,500 tail live in GetSoqucoinBlockSubsidy (soqucoin.cpp).
        consensus.nSubsidyHalvingInterval = 250000;
        consensus.nInitialSubsidy = 100000; // 47B launch reward
        consensus.nMajorityEnforceBlockUpgrade = 1500;
        consensus.nMajorityRejectBlockOutdated = 1900;
        consensus.nMajorityWindow = 2000;
        // BIP34 is never enforced in Soqucoin v2 blocks, so we enforce from v3
        consensus.BIP34Height = 1034383;
        consensus.BIP34Hash = uint256S("0x80d1364201e5df97e696c03bdd24dc885e8617b9de51e453c10a4f629b1e797a");
        consensus.BIP65Height = 3464751;                                                                     // 34cd2cbba4ba366f47e5aa0db5f02c19eba2adf679ceb6653ac003bdc9a0ef1f - first v4 block after the last v3 block
        consensus.BIP66Height = 1034383;                                                                     // 80d1364201e5df97e696c03bdd24dc885e8617b9de51e453c10a4f629b1e797a - this is the last block that could be v2, 1900 blocks past the last v2 block
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20;
        consensus.nPowTargetTimespan = 4 * 60 * 60;                                                          // pre-digishield: 4 hours
        consensus.nPowTargetSpacing = 60;                                                                    // 1 minute
        consensus.fDigishieldDifficultyCalculation = false;
        consensus.nCoinbaseMaturity = 30;
        // Finality horizon (Analysis [A], 2026-06-22): refuse reorgs deeper than
        // this. 288 blocks ~= 4.8h at 1-min spacing, >>any natural reorg depth.
        // TEAM-TUNABLE policy value (smaller = faster finality + smaller
        // double-spend window; must stay well above the deepest natural reorg).
        // Propagates into digishieldConsensus via the copy below.
        consensus.nMaxReorgDepth = 288;
        consensus.fSimplifiedRewards = true; // Fixed 500K SOQ/block from genesis (no Dogecoin random rewards)
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowAllowDigishieldMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 9576; // 95% of 10,080
        consensus.nMinerConfirmationWindow = 10080;      // 60 * 24 * 7 = 10,080 blocks, or one week
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;   // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        // XXX: BIP heights and hashes all need to be updated to Soqucoin values
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800;   // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0;            // Disabled


        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // LatticeFold+ activation — ALWAYS_ACTIVE from genesis (April 2026 decision)
        // SOQ-P002: No BIP9 signaling needed — new chain, privacy from block 0
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-P003: Lattice-BP++ Range Proofs — NOT ACTIVE (future soft-fork)
        // Post-quantum confidential transaction amount hiding using Ring-LWE
        // commitments. Activation requires separate soft-fork after audit.
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].nStartTime = 0;  // Not started
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].nTimeout = 0;    // Never activates

        // SOQ-AUD2-002: USDSOQ Stablecoin — NOT ACTIVE (future BIP9 soft-fork)
        // Activation requires miner signaling after Halborn audit.
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime = 0;  // Not started
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nTimeout = 0;    // Never activates

        // SOQ-COV-012 [DOC]: Covenant opcode BIP9 activation — MAINNET
        // ============================================================
        // CTV (BIP 119), APO (BIP 118), and CSFS (BIP 348) are NOT YET
        // activated on mainnet. Activation is gated on Halborn Phase 2
        // audit sign-off covering SOQ-COV-001 through SOQ-COV-012.
        //
        // Activation procedure:
        //   1. Halborn Phase 2 audit completes and signs off on covenant fixes
        //   2. nStartTime is set to the UNIX timestamp of a future signaling window
        //   3. nTimeout is set to nStartTime + 1 year (standard BIP9 window)
        //   4. STANDARD_SCRIPT_VERIFY_FLAGS in policy.h is updated to include the
        //      relevant SCRIPT_VERIFY_* flags so mempool enforces covenant policy
        //
        // Until activation:
        //   - CTV/APO/CSFS scripts evaluate as NOP (harmless; soft-fork safe)
        //   - Covenant transactions are NOT standard and will not relay
        //   - Regtest and stagenet have these flags ALWAYS_ACTIVE for testing
        //
        // Reference: DL-COVENANT-POST-AUDIT-HARDENING.md, SOQ-COV-012
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 audit
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nTimeout = 0;    // Not yet scheduled

        consensus.vDeployments[Consensus::DEPLOYMENT_APO].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 sighash audit
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nTimeout = 0;    // Not yet scheduled

        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 CSFS audit
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nTimeout = 0;    // Not yet scheduled

        // SOQ-AUD2-009: P2WSH-Dilithium (witness v6) — NOT ACTIVE on mainnet
        // Enables covenant script execution (CTV vaults, CSFS oracles, L2SOQ Lightning).
        // BIP9 activation post-audit: set nStartTime to future timestamp, miners signal bit 10.
        // See DL-P2WSH-DILITHIUM.md for full design.
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 audit
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nTimeout = 0;    // Not yet scheduled

        // SOQ-ARCH-003: UTXO Cost — NOT ACTIVE on mainnet (pending Phase 2 audit)
        // Cardano-style utxoCostPerByte: min output value = UTXO_COST_PER_BYTE × output_size.
        // BIP9 activation post-Phase 2 audit: set nStartTime, miners signal bit 11.
        // See DL-SOQ-FEE-ARCHITECTURE-V3.md.
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].bit = 11;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 audit
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nTimeout = 0;    // Not yet scheduled

        // OP_CHECKDILITHIUMKEYHASH — NOT ACTIVE on mainnet (pending Phase 2 audit)
        // Key-committed Dilithium signature verification for eLTOO 2-of-2 multisig.
        // Enables L2SOQ Lightning channels with Dilithium pubkeys > MAX_SCRIPT_ELEMENT_SIZE.
        // BIP9 activation post-audit: set nStartTime, miners signal bit 12.
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 audit
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nTimeout = 0;    // Not yet scheduled

        // DL-V6-CONTROLFLOW-RESTORE: restore branch/timelock/hashlock opcodes in v6 EvalScript.
        // BIP9 activation post-audit: set nStartTime, miners signal bit 13.
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].bit = 13;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nStartTime = 0;  // NOT ACTIVE: pending Halborn Phase 2 audit
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nTimeout = 0;    // Not yet scheduled


        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000e993d2aa86cf246a49b"); // 5,050,000

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");
        consensus.dilithiumOnlyHeight = 0;
        consensus.dilithiumOnlyHeight = 0;
        consensus.nLatticeFoldActivationHeight = 0; // Active from genesis

        // AuxPoW parameters
        consensus.nAuxpowChainId = 0x5351;   // "SQ" = Soqucoin (unique ID, avoids Dogecoin collision)
        consensus.fStrictChainId = false;    // Allow legacy blocks without embedded chain ID
        consensus.fAllowLegacyBlocks = true; // Allow both legacy Scrypt AND AuxPoW blocks
        consensus.nAuxpowStartHeight = 0;    // AuxPoW from genesis — merge mining available from block 0
        consensus.nHeightEffective = 0;

        // CONSENSUS FIX (DL-MAINNET-DIFFICULTY-TRANSITION):
        // DigiShield per-block difficulty adjustment from block 1 (matching stagenet).
        // Soqucoin launches from its own genesis — Dogecoin's 145000 is meaningless here.
        // DigiShield must activate early so the chain can handle AuxPoW hashrate
        // without being stuck on 240-block retarget intervals.
        //
        // Since AuxPoW is allowed from block 0 (nAuxpowStartHeight=0), and DigiShield
        // activates at block 1, we merge them into a single consensus tier at height 1.
        // Block 0 (genesis) uses base consensus; block 1+ uses DigiShield + AuxPoW.
        digishieldConsensus = consensus;
        digishieldConsensus.nHeightEffective = 1;
        digishieldConsensus.fSimplifiedRewards = true;
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.nPowTargetTimespan = 60; // post-digishield: 1 minute
        digishieldConsensus.nCoinbaseMaturity = 240;

        // AuxPoW + DigiShield from block 1 (merged tier).
        // Both standalone Scrypt blocks (solo miners) and AuxPoW blocks
        // (merge-mining pools) accepted. fAllowLegacyBlocks = true enables
        // Dogecoin-model dual mining. nAuxpowStartHeight=0 on base consensus
        // means AuxPoW blocks are valid from genesis, but the DigiShield
        // difficulty adjustment kicks in at block 1 via this tier.
        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.nHeightEffective = 1; // Same tier as DigiShield — BST valid
        auxpowConsensus.fAllowLegacyBlocks = true;

        // Assemble the binary search tree of consensus parameters
        // Simple two-node tree: genesis (left) and block 1+ (right)
        pConsensusRoot = &consensus;
        consensus.pRight = &auxpowConsensus;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf5;
        pchMessageStart[1] = 0xe1;
        pchMessageStart[2] = 0xd5;
        pchMessageStart[3] = 0xc1;
        nDefaultPort = 33388;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1386325540, 99943, 0x1e0ffff0, 1, 88 * COIN);

        // Phase 4: mainnet genesis re-mined 2026-06-16 (DL-GENESIS-REMINE.md)
        // Original nonce 99943 is still valid under byte-less CTxOut serialization.
        // Scrypt PoW: 0000026f3f7874ca0c251314eaed2d2fcf83d7da3acfaacf59417d485310b448
        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        assert(consensus.hashGenesisBlock == uint256S("0x1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691"));
        assert(genesis.hashMerkleRoot == uint256S("0x5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69"));

        // SOQ-H3: Lattice-BP++ consensus seed — derived from genesis hash
        consensus.latticeBPSeed = ComputeLatticeBPSeed(
            consensus.hashGenesisBlock,
            "soqucoin-latticebp-params-v1",
            "N=256,Q=8380417,K=4,range=64");
        digishieldConsensus.latticeBPSeed = consensus.latticeBPSeed;
        auxpowConsensus.latticeBPSeed = consensus.latticeBPSeed;

        // Soqucoin mainnet DNS seeds — DNS-only (grey cloud) A records in Cloudflare
        // These resolve to SOQUPOOL geo-distributed mining mesh nodes
        vSeeds.push_back(CDNSSeedData("soqu.org", "seed1.soqu.org", true));
        vSeeds.push_back(CDNSSeedData("soqu.org", "seed2.soqu.org", true));
        vSeeds.push_back(CDNSSeedData("soqu.org", "seed3.soqu.org", true));

        base58Prefixes[PUBKEY_ADDRESS] = boost::assign::list_of(63)(22).convert_to_container<std::vector<unsigned char> >(); // C5 prefix for mainnet
        base58Prefixes[SCRIPT_ADDRESS] = boost::assign::list_of(9)(18).convert_to_container<std::vector<unsigned char> >();  // 95 prefix
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 158);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0xfa)(0xca)(0xfd).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0xfa)(0xc3)(0x98).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        // Mainnet checkpoints — genesis only (updated after genesis re-mine)
        // Additional checkpoints will be added as the chain matures
        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
                (0, consensus.hashGenesisBlock)
        };

        // Mainnet chain transaction data — fresh chain, no history yet
        // Updated periodically as chain grows (timestamp, total txns, txns/sec)
        chainTxData = ChainTxData{
            0,    // No checkpoint timestamp yet — updated after genesis
            0,    // No transactions yet
            0.0   // No estimated tx rate yet
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams
{
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;
    Consensus::Params minDifficultyConsensus;

public:
    CTestNetParams()
    {
        strNetworkID = "test";
        bech32HRP = "sq";

        // Blocks 0 - 144999 are pre-Digishield
        consensus.nHeightEffective = 0;
        consensus.nPowTargetTimespan = 4 * 60 * 60; // pre-digishield: 4 hours
        consensus.fDigishieldDifficultyCalculation = false;
        consensus.nCoinbaseMaturity = 30;
        consensus.nMaxReorgDepth = 288; // Finality horizon (Analysis [A]); see CMainParams. Propagates into digishieldConsensus.
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowAllowDigishieldMinDifficultyBlocks = false;
        consensus.nSubsidyHalvingInterval = 250000; // 47B schedule — mirror mainnet (bead c61)
        consensus.nInitialSubsidy = 100000; // 47B launch reward
        consensus.nMajorityEnforceBlockUpgrade = 501;
        consensus.nMajorityRejectBlockOutdated = 750;
        consensus.nMajorityWindow = 1000;
        // BIP34 is never enforced in Soqucoin v2 blocks, so we enforce from v3
        consensus.BIP34Height = 708658;
        consensus.BIP34Hash = uint256S("0x21b8b97dcdb94caa67c7f8f6dbf22e61e0cfe0e46e1fff3528b22864659e9b38");
        consensus.BIP65Height = 1854705;                                                                     // 955bd496d23790aba1ecfacb722b089a6ae7ddabaedf7d8fb0878f48308a71f9
        consensus.BIP66Height = 708658;                                                                      // 21b8b97dcdb94caa67c7f8f6dbf22e61e0cfe0e46e1fff3528b22864659e9b38 - this is the last block that could be v2, 1900 blocks past the last v2 block
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20;
        consensus.nPowTargetTimespan = 4 * 60 * 60;                                                          // pre-digishield: 4 hours
        consensus.nPowTargetSpacing = 60;                                                                    // 1 minute
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 2880; // 2 days (note this is significantly lower than Bitcoin standard)
        consensus.nMinerConfirmationWindow = 10080;      // 60 * 24 * 7 = 10,080 blocks, or one week
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;   // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        // XXX: BIP heights and hashes all need to be updated to Soqucoin values
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800;   // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;


        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // LatticeFold+ activation — ALWAYS_ACTIVE from genesis (April 2026 decision)
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-P003: Lattice-BP++ Range Proofs — ACTIVE on stagenet for integration testing
        // Mainnet remains NEVER_ACTIVE pending Halborn audit. See DL-LATTICE-RANGE-PROOF.md.
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-AUD2-002: USDSOQ Stablecoin — ACTIVE on stagenet for integration testing
        // Mainnet remains NEVER_ACTIVE pending Halborn audit. See DL-USDSOQ-STABLECOIN.md.
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_APO].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-AUD2-009: P2WSH-Dilithium (witness v6) — ALWAYS_ACTIVE on testnet/stagenet
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-ARCH-003: UTXO Cost — ALWAYS_ACTIVE on testnet for integration testing
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].bit = 11;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // OP_CHECKDILITHIUMKEYHASH — ALWAYS_ACTIVE on testnet for integration testing
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // DL-V6-CONTROLFLOW-RESTORE — ALWAYS_ACTIVE on testnet for eLTOO/HTLC integration testing
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].bit = 13;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");
        consensus.dilithiumOnlyHeight = 0;
        consensus.nLatticeFoldActivationHeight = 0; // Active immediately for testing

        // AuxPoW parameters
        consensus.nAuxpowChainId = 0x5351; // "SQ" = Soqucoin (unique ID, avoids Dogecoin collision)
        consensus.fStrictChainId = false;  // Allow legacy blocks without embedded chain ID
        consensus.nHeightEffective = 0;
        consensus.fAllowLegacyBlocks = true; // Allow both legacy Scrypt AND AuxPoW blocks
        consensus.nAuxpowStartHeight = 158100; // Match auxpowConsensus.nHeightEffective

        // Blocks 145000 - 157499 are Digishield without minimum difficulty on all blocks
        digishieldConsensus = consensus;
        digishieldConsensus.nHeightEffective = 145000;
        digishieldConsensus.nPowTargetTimespan = 60; // post-digishield: 1 minute
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.fSimplifiedRewards = true;
        digishieldConsensus.fPowAllowMinDifficultyBlocks = false;
        digishieldConsensus.nCoinbaseMaturity = 240;
        digishieldConsensus.dilithiumOnlyHeight = 0;

        // Blocks 157500 - 158099 are Digishield with minimum difficulty on all blocks
        minDifficultyConsensus = digishieldConsensus;
        minDifficultyConsensus.nHeightEffective = 157500;
        minDifficultyConsensus.fPowAllowDigishieldMinDifficultyBlocks = true;
        minDifficultyConsensus.fPowAllowMinDifficultyBlocks = true;
        minDifficultyConsensus.dilithiumOnlyHeight = 0;

        // Enable AuxPoW at 158100
        auxpowConsensus = minDifficultyConsensus;
        auxpowConsensus.nHeightEffective = 158100;
        auxpowConsensus.fPowAllowDigishieldMinDifficultyBlocks = true;
        auxpowConsensus.fAllowLegacyBlocks = true;
        auxpowConsensus.dilithiumOnlyHeight = 0;

        // Assemble the binary search tree of parameters
        pConsensusRoot = &digishieldConsensus;
        digishieldConsensus.pLeft = &consensus;
        digishieldConsensus.pRight = &minDifficultyConsensus;
        minDifficultyConsensus.pRight = &auxpowConsensus;

        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdc;
        nDefaultPort = 44556;
        nPruneAfterHeight = 1000;

        // Soqucoin Testnet3 Genesis Block - Dec 2025
        // Unique genesis isolates Soqucoin from Dogecoin testnet
        // "First quantum-resistant Scrypt chain - Soqucoin Testnet3 Dec 2025"
        genesis = CreateGenesisBlockTestnet3(1766813480, 1014070, 0x1e0ffff0, 1, 88 * COIN);

        // TODO: Re-mine testnet3 genesis with new nonce after CTxOut format change
        // Testnet3 is being retired in favor of stagenet.
        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        minDifficultyConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        // Genesis hash assertion deferred — testnet3 is being retired

        // SOQ-H3: Lattice-BP++ consensus seed
        consensus.latticeBPSeed = ComputeLatticeBPSeed(
            consensus.hashGenesisBlock,
            "soqucoin-latticebp-params-v1",
            "N=256,Q=8380417,K=4,range=64");
        digishieldConsensus.latticeBPSeed = consensus.latticeBPSeed;
        minDifficultyConsensus.latticeBPSeed = consensus.latticeBPSeed;
        auxpowConsensus.latticeBPSeed = consensus.latticeBPSeed;

        // Clear all Dogecoin seeds - Soqucoin testnet is isolated
        vSeeds.clear();
        // Soqucoin DNS seed nodes - January 2026
        vSeeds.push_back(CDNSSeedData("soqu.org", "seed1.soqu.org")); // Testnet3 VPS
        vSeeds.push_back(CDNSSeedData("soqu.org", "seed2.soqu.org")); // Stagenet VPS
        vSeeds.push_back(CDNSSeedData("soqu.org", "seed3.soqu.org")); // Pinode (home node)

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 113); // 0x71
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196); // 0xc4
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 241);     // 0xf1
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xcf).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of(0, uint256S("0x000001cf9dfb272cb071d8490aa5a1108897de05bfa4b95f48097a2d4f0e7809"))};

        chainTxData = ChainTxData{
            0,
            0,
            0};
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams
{
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;

public:
    CRegTestParams()
    {
        strNetworkID = "regtest";
        bech32HRP = "sq";
        consensus.nSubsidyHalvingInterval = 150;
        // Regtest keeps the historical 500,000 launch reward as a test fixture: the
        // qa/rpc-tests functional suite hardcodes 500K-coinbase balances. Mainnet
        // economics (100K) are exercised by the C++ subsidy unit tests, not regtest.
        consensus.nInitialSubsidy = 500000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351;                                                                        // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251;                                                                        // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 1;
        consensus.nPowTargetTimespan = 4 * 60 * 60;                                                          // pre-digishield: 4 hours
        consensus.nPowTargetSpacing = 1;                                                                     // regtest: 1 second blocks
        consensus.fDigishieldDifficultyCalculation = false;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 540; // 75% for testchains
        consensus.nMinerConfirmationWindow = 720;       // Faster than normal for regtest (2,520 instead of 10,080)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;


        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // LatticeFold+ activation — ALWAYS_ACTIVE for regtest
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-P003: Lattice-BP++ Range Proofs — ALWAYS_ACTIVE for regtest
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-AUD2-002: USDSOQ Stablecoin — ALWAYS_ACTIVE for regtest
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_APO].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-AUD2-009: P2WSH-Dilithium (witness v6) — ALWAYS_ACTIVE for regtest
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-ARCH-003: UTXO Cost — ALWAYS_ACTIVE for regtest
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].bit = 11;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // OP_CHECKDILITHIUMKEYHASH — ALWAYS_ACTIVE for regtest
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // DL-V6-CONTROLFLOW-RESTORE — ALWAYS_ACTIVE for regtest (eLTOO/HTLC unit + functional tests)
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].bit = 13;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        // AuxPow parameters
        consensus.nAuxpowChainId = 0x5351;   // "SQ" = Soqucoin (unique ID, avoids Dogecoin collision)
        consensus.fStrictChainId = false;    // Allow legacy blocks without embedded chain ID
        consensus.fAllowLegacyBlocks = true; // Allow both legacy Scrypt AND AuxPoW blocks
        consensus.nAuxpowStartHeight = 20;   // Regtest: match auxpowConsensus.nHeightEffective

        // Soqucoin parameters
        consensus.fSimplifiedRewards = true;
        consensus.nCoinbaseMaturity = 60; // For easier testability in RPC tests
        consensus.nMaxReorgDepth = 0;      // Disabled on regtest; functional tests opt in via -maxreorgdepth (see UpdateMaxReorgDepth)

        digishieldConsensus = consensus;
        digishieldConsensus.nHeightEffective = 10;
        digishieldConsensus.nPowTargetTimespan = 1; // regtest: also retarget every second in digishield mode, for conformity
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.dilithiumOnlyHeight = 0;

        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.fAllowLegacyBlocks = false;
        auxpowConsensus.nHeightEffective = 20;
        auxpowConsensus.dilithiumOnlyHeight = 0;

        // Assemble the binary search tree of parameters
        digishieldConsensus.pLeft = &consensus;
        digishieldConsensus.pRight = &auxpowConsensus;
        pConsensusRoot = &digishieldConsensus;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 88 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        // Phase 4: regtest genesis hash changed — byte-less CTxOut serialization.
        // Old (byte-ful): 0x22ad706761265b8c05cbc33ff212c1ad7c049afc4e15fc8c04f7e6824da9630f
        assert(consensus.hashGenesisBlock == uint256S("0x3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5"));

        // SOQ-H3: Lattice-BP++ consensus seed
        consensus.latticeBPSeed = ComputeLatticeBPSeed(
            consensus.hashGenesisBlock,
            "soqucoin-latticebp-params-v1",
            "N=256,Q=8380417,K=4,range=64");
        digishieldConsensus.latticeBPSeed = consensus.latticeBPSeed;
        auxpowConsensus.latticeBPSeed = consensus.latticeBPSeed;
        // Old merkle root (byte-ful): 0xef6d97da4c49ec2be1f68b1608b62e15645237767a8a5f6e16747ede9b114920
        assert(genesis.hashMerkleRoot == uint256S("0x5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of(0, uint256S("0x3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5"))};

        chainTxData = ChainTxData{
            0,
            0,
            0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111); // 0x6f
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196); // 0xc4
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // 0xef
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }

    void UpdateMaxReorgDepth(int nMaxReorgDepth)
    {
        consensus.nMaxReorgDepth = nMaxReorgDepth;
        digishieldConsensus.nMaxReorgDepth = nMaxReorgDepth;
    }
};
static CRegTestParams regTestParams;

/**
 * Stagenet - Mainnet rehearsal network
 * Mirrors mainnet consensus exactly:
 * - Real difficulty adjustment (fPowAllowMinDifficultyBlocks = false)
 * - Dilithium, PAT, LatticeFold+ all ALWAYS_ACTIVE from genesis
 * - Lattice-BP++ NOT_ACTIVE (future soft-fork, same as mainnet)
 * - fRequireStandard = true (reject non-standard txs)
 */
class CStageNetParams : public CChainParams
{
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;

public:
    CStageNetParams()
    {
        strNetworkID = "stagenet";
        bech32HRP = "ssq"; // stagenet soqucoin

        // 47B schedule — stagenet mirrors mainnet economics (bead c61). At 250K
        // blocks/halving the first halving is ~174d out, so stagenet exercises the
        // schedule via unit tests, not by waiting for a live halving.
        consensus.nSubsidyHalvingInterval = 250000;
        consensus.nInitialSubsidy = 100000; // 47B launch reward (stagenet mirrors mainnet)
        consensus.nMajorityEnforceBlockUpgrade = 1500;
        consensus.nMajorityRejectBlockOutdated = 1900;
        consensus.nMajorityWindow = 2000;
        consensus.BIP34Height = 100; // Must be > 16 to avoid OP_N vs push-byte encoding mismatch in coinbase
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 4 * 60 * 60; // 4 hours
        consensus.nPowTargetSpacing = 60;           // 1 minute
        consensus.fDigishieldDifficultyCalculation = true;
        consensus.fPowAllowMinDifficultyBlocks = false;  // SOQ-INFRA-005: MUST be false to emulate mainnet
        consensus.fPowAllowDigishieldMinDifficultyBlocks = false;  // SOQ-INFRA-005: real Digishield retarget
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512;
        consensus.nMinerConfirmationWindow = 2016;
        consensus.fSimplifiedRewards = true;
        consensus.nCoinbaseMaturity = 30;
        consensus.nMaxReorgDepth = 288; // Finality horizon (Analysis [A]); mainnet rehearsal — match CMainParams.

        // Dilithium only from genesis
        consensus.dilithiumOnlyHeight = 0;

        // LatticeFold+ ALWAYS_ACTIVE from genesis (matches mainnet April 2026 decision)
        consensus.nLatticeFoldActivationHeight = 0;

        // BIP9 deployments - all active from genesis (Dilithium)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;


        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // LatticeFold deployment - height based, not BIP9
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-P003: Lattice-BP++ Range Proofs — ALWAYS_ACTIVE on stagenet
        // Enables confidential transaction testing. Mainnet remains NOT_ACTIVE pending audit.
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-AUD2-002: USDSOQ Stablecoin — ALWAYS_ACTIVE on stagenet
        // Enables mint/burn/freeze testing. Mainnet remains NOT_ACTIVE pending audit.
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-COV-012 [DOC]: Covenant opcode activation — STAGENET / REGTEST
        // ================================================================
        // CTV (BIP 119), APO (BIP 118), and CSFS (BIP 348) are ALWAYS_ACTIVE
        // on stagenet and regtest from genesis. This is intentional:
        //
        //   - Enables full integration testing of covenant scripts, vaults,
        //     eltoo payment channels, and oracle contracts before mainnet
        //   - Allows the covenant_tests.cpp test suite to run against live
        //     regtest nodes without miner activation signaling
        //   - Stagenet mirrors mainnet economics but activates all features
        //     from genesis so developers can test the full feature set
        //
        // The ALWAYS_ACTIVE status does NOT indicate these features are
        // production-ready for mainnet. Mainnet activation is gated on
        // Halborn Phase 2 audit sign-off. See chainparams.cpp mainnet section
        // and DL-COVENANT-POST-AUDIT-HARDENING.md, SOQ-COV-012.
        //
        // Security implication: Since stagenet is a test network, the risk of
        // pre-audit covenant bugs being exploited for real funds is zero.
        // Stagenet SOQ has no monetary value.
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY — see note above
        consensus.vDeployments[Consensus::DEPLOYMENT_CTV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_APO].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY — see note above
        consensus.vDeployments[Consensus::DEPLOYMENT_APO].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY — see note above
        consensus.vDeployments[Consensus::DEPLOYMENT_CSFS].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-AUD2-009: P2WSH-Dilithium (witness v6) — ALWAYS_ACTIVE on stagenet
        // Enables covenant script execution for live testing. See DL-P2WSH-DILITHIUM.md.
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY
        consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // SOQ-ARCH-003: UTXO Cost — ALWAYS_ACTIVE on stagenet for integration testing
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].bit = 11;
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY
        consensus.vDeployments[Consensus::DEPLOYMENT_UTXO_COST].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // OP_CHECKDILITHIUMKEYHASH — ALWAYS_ACTIVE on stagenet for eLTOO testing
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY
        consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // DL-V6-CONTROLFLOW-RESTORE — ALWAYS_ACTIVE on stagenet for the eLTOO/HTLC e2e (ratchet, settlement, HTLC)
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].bit = 13;
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;  // STAGENET ONLY
        consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // USDSOQ Authority Keys - 2-of-3 ML-DSA-44 multisig (FIPS 204)
        // Keys control USDSOQ mint/burn/freeze. Generated 2026-05-27T04:46:27Z
        // Private key material stored in ADDRESS_REGISTRY.md and soq-signer authority keystore.
        consensus.usdsoqAuthorityKeys = {
            "3f13d3d3fc8cec4b821524576607a873028be87b354b4ceb876322ef06ff0f66c8d475f32689ba66dc665ebb53393a795933c122c06d3a639a1e82579561c5628b7bac1a7eed9723741b540a158e3aa561719aa85e6f1f27e738c7e288bbbdf5eae599d5c2cb008f3de2bcba1db7723b3e980229db5c06fcec74379172970fe0d08469ffa11027455b675f3c4faea59155fb8d809bef6c8bb4544a599c08324fd857056ac4dddc6b0f3f8fed9819f82895ba79693fdfe781b9a4678eaf51b55503fe0c9286efc3d7fb47505321bcbc197d98b7a1f8754b4b23813823c4bc181b721c9803012548a2f0ee20294217715873cc48a3bf72707d09d3509dd95561dc97c212d0ea1b8df0998420e2043e19db070db6780647d4eba9c1675fa1ad69bb75d223ed22937a11e22582f8bb8f2b10acdb986dcbf8100c704c7f9960560c01051c7f9614d557af356ded0fe9f0ff73c16708c527744860291a607a235bba0077685dfe758472c1801e0ef004eaca656bc85a7cbb0a1e260f6403e3f5b38479d9fb276ba8b5b333e85955171fa4f817da8ec66bd0d1ceeb4fca019ee54962c84bda7d114f8c7c106f8abb67877c79bd6c97d69f2dea69688170812512c349eb09eb9d0a7d60eaf0215b10f53d22cdd0f872b1dc3a5d675338f4b980bae5eebc13af372ab1b2ff8ebd1b865440acac92e30fcc98734a1678296c57d8af001dc053203dcd167e8847f1076b78a807e19abafe1a8724b3ddd81ad772af6a5704a61a1a3be1a2c7023d2b17f27b4db68200df67aa2141f229315bd82d16440dc03deb0e3f0d96b7fe5f25c5fc409fb2259d693d1829199cce3a860994bd5535afcaa91cd7f0000a71ff005498e80858e21404676312bf55cb7eae15a142aac354028810b248a3be2432ab1acc41fda00ff105897f0225f40772661040399f3e8288c07e89968fa5ee60d098ffaf9528f2950915ca0f10b6f774385125d8c3ab320d15dbb62313669129a69b6369d52201fb499f1a1fa63b9e76b51030f8516dd4cad69c9c4ea5efd6bea1148aa7773d1e183a0ade2bfd707a2e436b73874d8a60fd2548e358511cb10747c4a02ac469a2add5d835d8631a76e500f080d29e561eed50a3d32bd7032698363e991218e74037544f65726fcad1597813c2fdedcaf047f211526c3915f18fff72ca950889415d414a1230a7448a97e21d4eb42fca35c54dd24397bf8b16c1712697770f3035b40577ca77c1f65973f29a087e272164c94d73a3547496fe4c890e2a4a7517e45fe885b7b0d2c26077cca73fd91c97ee115053b6ce300a441a963334786b63b3018a7b1a5b0d1728b00e7986c09708161559875204dbd729dadc0168e4d90bc937f9b1a0d27bee04945cb428c958e7f8236a9de7aa726133865542e1aba77ddfbc459c7c5a5aeeabcf5ae93bcc81432929aa17bafa6c106957a9f3fce333b1d04f423e90a4da84b0e85fc139597be4f3002b41cd8fec2b67f711973d6f218d01bddb65bf52b067ede05c302fa2e1f7a9a8eeb94c3125dc0ec1d0bd39a5c7797886b3826631c839b600be2df50bcc8322ca960faa84012a71dd562a7f695e4f31027252b2c5db2ee6c36815c2092ec7d6fb7cd381b56c47a1766875a33900c37f2ba46929a9fad1b7f0dc77126c80bcde0ac9ca6fc51fbff775ae908c4460e543b15686fe092e6aa01914d9ece7520c0f4f3a44591ded5c9bb313b089cbfc9724eadb6a659a7c9ea971c2243cac6827117f5cec2ed4a9ba80fdf1e4c6ff6dac643e01fec65feb5b0642df2fc6a8eae1fe1ad4b75c17ddc0060b933c2a52299fcd6c2eec5470d31a0fb768179d3b4bd617d3",
            "88ab756b23c4b4ee00d664ce402f1bc64ac2dc5ce08f63673806729af5352fd51678529a3119d2d7c6eb1ed531cd5a977a7d7956c62ae35dd929f3c314ce31833a1a31001cd5ebd35d9f4a90ce7458d5599f1f4889202bef98fe00f33b54cbf990a146bdfb48c5f3d2ca66af7db3d12eb66c008b9443ca655a651b23776ac156a46450f0664a2315abad65e5d78f57722003953085c65ddadb176c9f15f5baa25c863717c1e3c2692e285a0daf4a1da7b32ef88aef4ad625e8332dec5dc3eb4f62f61f1ba893937e3a25125848caa4d97e33cb9ae7b9ad3c54b019d4e5aa8259da3cbbb654e79c72868c3e9f53ac2cf433092d719ceb9f55f95a3a19199af32968034ede41158d1b3c6263bbf6ebbfee3322b5582f3635fc3a92e89d33c48033c7f0af0fb4a2fb0bc3a0d1246dbf817103da01e1604ad74a7e2b49a02d8b882d24056a5873b74ec1a3d5936e835af29c64d2ddabd2d7af7ce9f74992e5ee17e1362e92df5517ce91467ee4da76e8b9a359e9f464d8276b2fdc8d99c4e3c669c97a6821de2c00990313430296622546dd8568f3c1345e5ba8fbf4c993786625712feec5d57d07ed09095addfb4dbdd7e4d57809d3b8915ce340300f22d5bf4e8961a2d8ff6c27cc0e8a3ab70603c65e040bcf3984add59a849e0c289df494341cc4d7ae4ccb7eb47c0dd3c5c17c16aa9df02cfce0dac541f807654e23efd3eb3a9f54355df0b0230f2460704b96c19936df83dc4e38dbbad86dadef9fd47737610a3be55b452e53762e3c082f313612f1f4750100a1695d7576e48e85a7fae514b9e470b05418330e930839027ccecd7ed4e03923aaf9ed33aa7811c90e3a42ba3c52b8ef810e1708684270d8923103f79560fba1bb0d61fc7bc9bb8ae3f84a4830d7e4ddac270a95a1891ec1bf0a3691ae5785e06c80298c3a4793ec42f5f102ada4ee29c883cf385cb44d052852a3f72253789ba3d28495ecce5ad907f58196321a497c29456c12957860b4c0639afce7b542af42611046a387199296a5ce9b29bde05f948dc44c0c25cba13d6598b7c23de7f617e2e9f6a71e2d99adf6c5aca4f679d3a18c861b5b7a51e0853491d2aa6ff3dc0dbd18f8ca81d48f33a611482216f8853653935ee8a25bcca5902a1d48538fad33c7b31988b8f4cf6fc4e4976136fd227e5e54e9794e9915599a1073957e5d7fabf4f42e752047ab4328b9b7c67ba21fd1dcb5226ca088547535835c126d7fceec8b3ada0fa25713d0abd0f34f9ffdc201de542a304c13087eb4f5424149389733a446b65b306ad65b686c367bfa60b698c0a425399370224e401f8beac293c1760e4d1a0af18951ca14ed0c1f1340fe803c87e6b263fb2f4f11a73cf565c8880d3718a2416c3b176c6bb18365a896cf3c684859a52db5800506dd7897f5a7867bdb6a3a81b8f90855c4963ff9cd72b0d2712586a39d019cb1024e32d9caa7581927d49e339b805b4d2cc3610a987a50f989c281b391008f520149e4710f2fb1faa34ec3e86961649b4d2b784bf1d6dd4a976d2382ddf8d066534404bfc463f49ca3d6709f7923119736e1712eef1c2571ef5ca1618aa30f72a3ab3de879e26414c6080d42331c8e0cf6e65db45ed04e58a125d74baea33b90be4b8e45b24d5593cd17cdf94e0070a613c9e54e0975b4318e604d2c7a33abc7d4750f501e8ba1b45028544fa028596072767327e515173ae3e0899d3605effbfff6663bfa7d83b0d8532dc4580ee68388e9335bce1fa91158c919f42d73ab8cd48d85a78785200ea6f7d811ead446c1271a755ca85adaea1a5ee35deb4780e671fc46e5c0709ca895041b95dde511b71cbcec",
            "0e6734d74cb357881de3eafdeb0055bb88dd1de103a08f2bc4af58bdb0f4444a9102e6b5fcbb2ca26d8e8b59f9fef2ac6df6a3419433fe2b581fb95df5b10b2c3c6ba0c7fd6325014a6e5bcc229f632d004ea0ae5296f63331c9a65c7721800a8045bedfa774a6e1c9512927ae093f7c005001a381c12479c709b954ad5c2eb099d10c18e41f2aa42ef15e004bf5a1cefc4e658c506c588d2c3edabade9259d7db1e774505ab011202f637e237395e2a904271a42a8c9b3f39fedcaf6abb6c040c24142cdb4c6dd07eb5f35cb6880d2df0a6bd0a288544ecc7e7f3a87556c4f0019876e3b96faca222ba78e0ec7c02c5ad27481ce8d9e0e29975bd022fd68ad24a40636f168880249d0b0952e173a0920b5a52717b29b19b9d9cc1a9910857de49b92d995b7e035fab7fad7f23c8c391577d3ec2dfe9bb36600d607fae6fd7a5eb72c41cf0bb116de1f643199018233427cbabbd539290bf869c53d77c78ecf43b0ee5baa9127efc26cc765d2501645d16655afe7e0808982a896d80d05bea06aaecbafa804a57b667fec53527564857e5637c349a9c87de1fe684a6900f656a0734619e6bec0a5721cd9f4cc4bcee986445c20da3e96ce11039d8ac6f17e4d346a787e4487bae0719912da2d720919956532639b5526ef957b6bd9c9e6ae8e448966102e97a67e7a833e397b1ad3730f1447f292496cd0ab81269aadf5b464c4a5f569235b9aa612e39d1f7e01f4404aec0f5e96f16f33c13eeefbd66672768846e791ac4333a88055e4110d4e1d3760e2c45b6460b955ad30d23e4b82d7f2743d33b4440b3fba289fc13d10a19c4c7630cca75abc1e344958f5a06bf169dc7797958240f311a298d839b9d1f42b0b99ba3296206e596afd669fd7cb078641df98a0e2a20b41c96716bdf522a15211d0b85e43aba90a05166787e855b3aa776f17644b71a7cb5526db80ac6c2e6a4ca0f1da8ab13dc6ed4daf3394a73bfb7a2ec648b4037b1036bd8734a0134a42f3bd76442fa14405477516272a7b2630f0e95afc99d568bc3cf640369b09acb456b06abaaa2d2553bbd5df700ef848d38777dcbf9b7b0ab781bf67c3bece1794cbd516f15165907f829910772c2a8effd31541a8995d66fa71289acfb1d24e9bd29ea4a457c9fac7e8583d5eb6d605667b95a3c868acabdd2ca9cbe1d6f91378737b8d36ef99ff5dbd7162e702315fdf1e42faa3c3e9bcb04a83adeb30628e85d2a0f021e57a21f53142bfe128c8beeb23a0d4e17fbdb7858e3de396eadf69be230cc4dfbc1a7931182657627cd48bb0496bd66bad5f1ce2b02462ea48073d53717f274a19d625919bf613582a2e4dab5ae5d12142264f267308c68ecb20243643af3876ef56fb583810a4b31ecf207c5099475afced5a7f81903965d1e29f5dbc1ec7445ae5bce53f052e4bb64649fe24958f742d13c62e83d6333b53224fdf270007aea6a37b708a5b27a6e115dd3c73266e7cebfbadfd6b4d88f0bea727c9a942021c6e515825fab5433f1a7c1a1b19d1b59dff1d596869956e20f2ccaa91f6dbf771d6a3692ded1404fae9e4738bd482372c3165c3096cb15795edb8d9d26cd97c65f7dcf14bfef4057aa2b2abc5dddfc676b799d10509d7df54577b20289c52da7bfc0f2952d517f7ba9503de5931b9a98d7f867ad841e128aaa3446b6a1c8a70a94a171556320ab0d7396ff8eb631610fc19d3e937bd86949ee2ccfda40c434a11a0e3ebd84ae4fadf0f0f9e2e52faa019c9da87b18d262fe47aba0198e63ba2cb336381b81dbe7a3d7310e14b92ea1c432b1625a69d89e40aff6863b367351d78af9dd02472528817a80b235f895"
        };
        consensus.usdsoqAuthorityThreshold = 2;  // 2-of-3 multisig

        // SOQ-I005-STAGENET: Authority signature enforcement height.
        // Blocks 0–37200 contain pre-authority USDSOQ test mints (created via
        // CLI `usdsoqmint` RPC before ConnectBlock authority validation existed).
        // These TXs are structurally valid but lack authority witness signatures.
        // Authority signature verification is required from block 37201 onward.
        // See SECURITY_ISSUE_REGISTRY.md SOQ-I005-STAGENET.
        consensus.nUSDSOQAuthorityEnforcementHeight = 37201;

        // SOQ-I007-STAGENET: UTXO cost minimum enforcement height.
        // Blocks 0–37200 may contain outputs below UTXO_COST_PER_BYTE minimum
        // (mined before DEPLOYMENT_UTXO_COST code existed on stagenet fleet).
        // See SECURITY_ISSUE_REGISTRY.md SOQ-I007-STAGENET.
        consensus.nUtxoCostEnforcementHeight = 37201;
        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");

        // AuxPoW parameters - same as mainnet
        consensus.nAuxpowChainId = 0x5351; // "SQ" = Soqucoin
        consensus.fStrictChainId = false;
        consensus.nHeightEffective = 0;
        consensus.fAllowLegacyBlocks = true;
        consensus.nAuxpowStartHeight = 100;  // Stagenet Vanguard Window: solo blocks 0-99, AuxPoW from 100

        // Digishield from block 1
        digishieldConsensus = consensus;
        digishieldConsensus.nHeightEffective = 1;
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.nPowTargetTimespan = 60;

        // AuxPoW from block 100 — Dogecoin-model dual mining
        // Both standalone Scrypt and AuxPoW blocks accepted (matches mainnet)
        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.nHeightEffective = 100;
        auxpowConsensus.fAllowLegacyBlocks = true;

        pConsensusRoot = &digishieldConsensus;
        digishieldConsensus.pLeft = &consensus;
        digishieldConsensus.pRight = &auxpowConsensus;

        // Message start - unique for stagenet
        pchMessageStart[0] = 0x53; // 'S'
        pchMessageStart[1] = 0x54; // 'T'
        pchMessageStart[2] = 0x47; // 'G'
        pchMessageStart[3] = 0x4e; // 'N'
        nDefaultPort = 28333;
        nPruneAfterHeight = 1000;

        // Stagenet Genesis Block - April 2026 (v3 — Phase 4 byte-less CTxOut re-mine)
        // Unique genesis isolates Stagenet from all other networks
        // Timestamp: 1745769600 = 2026-04-27 12:00:00 UTC
        // Reward: 500,000 SOQ (matches mainnet emission schedule)
        // Nonce re-mined 2026-06-16 after Phase 4 CTxOut byte removal (DL-GENESIS-REMINE.md)
        // Scrypt PoW: 0000023c1d9d18db4abcb57b77efda4968cc3ee0e273870889d7381757c211cc
        genesis = CreateGenesisBlockStagenet(1745769600, 1215028, 0x1e0ffff0, 1, 500000 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        assert(consensus.hashGenesisBlock == uint256S("0x97df3ae79eaf5623c0feecfa1079439f8acdfea06a0f2acb4ef63c6b9ad91bb0"));

        // SOQ-H3: Lattice-BP++ consensus seed
        consensus.latticeBPSeed = ComputeLatticeBPSeed(
            consensus.hashGenesisBlock,
            "soqucoin-latticebp-params-v1",
            "N=256,Q=8380417,K=4,range=64");
        digishieldConsensus.latticeBPSeed = consensus.latticeBPSeed;
        auxpowConsensus.latticeBPSeed = consensus.latticeBPSeed;
        // Phase 4 byte-less merkle root (unchanged — same coinbase, new serialization)
        assert(genesis.hashMerkleRoot == uint256S("0x994391b757742376b24ebdd37b0fa9ebc11da47366ca8f9ac0a21094da350736"));

        vSeeds.clear();
        // Stagenet DNS seeds — resolved to our VPS IPs
        // IMPORTANT: These DNS records MUST be DNS-only (grey cloud) in Cloudflare,
        // NOT proxied (orange cloud), because P2P port 28333 is not HTTP.
        vSeeds.push_back(CDNSSeedData("soqu.org", "stagenet.soqu.org"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 125); // s prefix
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 100); // g prefix
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 253);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xcf).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_stagenet, pnSeed6_stagenet + ARRAYLEN(pnSeed6_stagenet));

        fMiningRequiresPeers = false;  // Allow solo mining during bootstrap
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;  // SOQ-INFRA-005: Match mainnet — reject non-standard txs
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of(0, consensus.hashGenesisBlock)};

        chainTxData = ChainTxData{
            0,
            0,
            0};
    }
};
static CStageNetParams stageNetParams;

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

const Consensus::Params* Consensus::Params::GetConsensus(uint32_t nTargetHeight) const
{
    if (nTargetHeight < this->nHeightEffective && this->pLeft != NULL) {
        return this->pLeft->GetConsensus(nTargetHeight);
    } else if (nTargetHeight > this->nHeightEffective && this->pRight != NULL) {
        const Consensus::Params* pCandidate = this->pRight->GetConsensus(nTargetHeight);
        if (pCandidate->nHeightEffective <= nTargetHeight) {
            return pCandidate;
        }
    }

    // No better match below the target height
    return this;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::STAGENET)
        return stageNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}

void UpdateRegtestMaxReorgDepth(int nMaxReorgDepth)
{
    regTestParams.UpdateMaxReorgDepth(nMaxReorgDepth);
}
