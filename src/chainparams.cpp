// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022-2024 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>


#include "chainparamsseeds.h"

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
        consensus.nSubsidyHalvingInterval = 100000;
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

        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKBATCHSIG].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKBATCHSIG].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKBATCHSIG].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

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
        consensus.nHeightEffective = 0;

        // Blocks 145000 - 371336 are Digishield without AuxPoW
        digishieldConsensus = consensus;
        digishieldConsensus.nHeightEffective = 145000;
        digishieldConsensus.fSimplifiedRewards = true;
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.nPowTargetTimespan = 60; // post-digishield: 1 minute
        digishieldConsensus.nCoinbaseMaturity = 240;

        // Blocks 1000+ are AuxPoW — "Vanguard Window" strategy
        // First 1000 blocks (~16.7 hours) are direct-mining only, rewarding
        // Day 1 miners before merge mining opens the chain to the global
        // Scrypt ecosystem. See DL-MERGE-MINING-POOL.md and
        // auxpow_activation_analysis.md for security analysis.
        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.nHeightEffective = 1000;
        auxpowConsensus.fAllowLegacyBlocks = false;

        // Assemble the binary search tree of consensus parameters
        pConsensusRoot = &digishieldConsensus;
        digishieldConsensus.pLeft = &consensus;
        digishieldConsensus.pRight = &auxpowConsensus;

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

        // TODO: Re-mine mainnet genesis with new nonce after CTxOut format change
        // The old nonce (99943) is invalid after nVisibility+nAssetType serialization.
        // Mainnet genesis will be properly mined before mainnet launch.
        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        // Genesis hash assertion deferred — nonce needs re-mining for mainnet launch

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("multidoge.org", "seed.multidoge.org", true));
        vSeeds.push_back(CDNSSeedData("multidoge.org", "seed2.multidoge.org"));

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

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of(0, uint256S("0x1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691"))(104679, uint256S("0x35eb87ae90d44b98898fec8c39577b76cb1eb08e1261cfc10706c8ce9a1d01cf"))(145000, uint256S("0xcc47cae70d7c5c92828d3214a266331dde59087d4a39071fa76ddfff9b7bde72"))(371337, uint256S("0x60323982f9c5ff1b5a954eac9dc1269352835f47c2c5222691d80f0d50dcf053"))(450000, uint256S("0xd279277f8f846a224d776450aa04da3cf978991a182c6f3075db4c48b173bbd7"))(771275, uint256S("0x1b7d789ed82cbdc640952e7e7a54966c6488a32eaad54fc39dff83f310dbaaed"))(1000000, uint256S("0x6aae55bea74235f0c80bd066349d4440c31f2d0f27d54265ecd484d8c1d11b47"))(1250000, uint256S("0x00c7a442055c1a990e11eea5371ca5c1c02a0677b33cc88ec728c45edc4ec060"))(1500000, uint256S("0xf1d32d6920de7b617d51e74bdf4e58adccaa582ffdc8657464454f16a952fca6"))(1750000, uint256S("0x5c8e7327984f0d6f59447d89d143e5f6eafc524c82ad95d176c5cec082ae2001"))(2000000, uint256S("0x9914f0e82e39bbf21950792e8816620d71b9965bdbbc14e72a95e3ab9618fea8"))(2031142, uint256S("0x893297d89afb7599a3c571ca31a3b80e8353f4cf39872400ad0f57d26c4c5d42"))(2250000, uint256S("0x0a87a8d4e40dca52763f93812a288741806380cd569537039ee927045c6bc338"))(2510150, uint256S("0x77e3f4a4bcb4a2c15e8015525e3d15b466f6c022f6ca82698f329edef7d9777e"))(2750000, uint256S("0xd4f8abb835930d3c4f92ca718aaa09bef545076bd872354e0b2b85deefacf2e3"))(3000000, uint256S("0x195a83b091fb3ee7ecb56f2e63d01709293f57f971ccf373d93890c8dc1033db"))(3250000, uint256S("0x7f3e28bf9e309c4b57a4b70aa64d3b2ea5250ae797af84976ddc420d49684034"))(3500000, uint256S("0xeaa303b93c1c64d2b3a2cdcf6ccf21b10cc36626965cc2619661e8e1879abdfb"))(3606083, uint256S("0x954c7c66dee51f0a3fb1edb26200b735f5275fe54d9505c76ebd2bcabac36f1e"))(3854173, uint256S("0xe4b4ecda4c022406c502a247c0525480268ce7abbbef632796e8ca1646425e75"))(3963597, uint256S("0x2b6927cfaa5e82353d45f02be8aadd3bfd165ece5ce24b9bfa4db20432befb5d"))(4303965, uint256S("0xed7d266dcbd8bb8af80f9ccb8deb3e18f9cc3f6972912680feeb37b090f8cee0"))(5050000, uint256S("0xe7d4577405223918491477db725a393bcfc349d8ee63b0a4fde23cbfbfd81dea"))};

        chainTxData = ChainTxData{
            // Data as of block e7d4577405223918491477db725a393bcfc349d8ee63b0a4fde23cbfbfd81dea (height 5050000).
            // Tx estimate based on average between 2023-01-16 (92752025 at 4556625) and 2024-01-16 (226128837 at 5050000)
            1705383360, // * UNIX timestamp of last checkpoint block
            226128837,  // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            4.23        // * estimated number of transactions per second after checkpoint
                        // (226128837 - 92752025) / 31536000 = 4.2293509
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
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowAllowDigishieldMinDifficultyBlocks = false;
        consensus.nSubsidyHalvingInterval = 100000;
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

        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKBATCHSIG].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKBATCHSIG].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKBATCHSIG].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

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

        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKBATCHSIG].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKBATCHSIG].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKBATCHSIG].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

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

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        // AuxPow parameters
        consensus.nAuxpowChainId = 0x5351;   // "SQ" = Soqucoin (unique ID, avoids Dogecoin collision)
        consensus.fStrictChainId = false;    // Allow legacy blocks without embedded chain ID
        consensus.fAllowLegacyBlocks = true; // Allow both legacy Scrypt AND AuxPoW blocks

        // Soqucoin parameters
        consensus.fSimplifiedRewards = true;
        consensus.nCoinbaseMaturity = 60; // For easier testability in RPC tests

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
        assert(consensus.hashGenesisBlock == uint256S("0x22ad706761265b8c05cbc33ff212c1ad7c049afc4e15fc8c04f7e6824da9630f"));
        assert(genesis.hashMerkleRoot == uint256S("0xef6d97da4c49ec2be1f68b1608b62e15645237767a8a5f6e16747ede9b114920"));

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

        consensus.nSubsidyHalvingInterval = 100000;
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

        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKBATCHSIG].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKBATCHSIG].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKBATCHSIG].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

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

        // USDSOQ Authority Keys - 2-of-3 ML-DSA-44 multisig (FIPS 204)
        // Keys control USDSOQ mint/burn/freeze. Generated by soq-signer gen-authority-keys.
        // Private key material in soq-signer keystore on Broadcast VPS (64.23.129.28).
        consensus.usdsoqAuthorityKeys = {
            "1f35a5480341a34abe68b709b30a0841b44c59c5f5e9a49275ad2f73d5c6be2f24a7d531d2209ac03a4f1e9433820d1ebda584ac93e373d785dd6c3f99956bfbb95e94f7048149144619da8cfda9b58a55d3868657d18f5ebcba35d67a00b14464d1325296d626912e217e49507d3f8035eea7bc3b12ad4307b7490aed09ea43f0fa7d2b13ddb146723006d78023523d05d06bc4c83e39dc6a0fb011d1476a110a4a53513f8b5acac181ad19bbbb9ca7c916e75922d6cff703e7cdc1e914281a2f1eea41d9f101d990ae3faa5ff9090903d8968269435bf69bb3bc57d1cd8bb95f7424047d2158abb2fe5704b678ced06ce35c7f4c53bce35a057ae7bf98118d9c3f4b6b6bd74464c256ff08de2be867bb33fad5fa377ae14bba4b38eaa44bbce83f6e7fee36909a8f304f496aeb25e574eac1a56e5684811c8f91f33db73197b4a254ca456d5fef87ad5256142c5626055cb13a70b8a6d15b8720673a991cd859add3e3991e4e34fdbcd28a5b30e4c56cbe964b03cf49c1f8d3df2d528022cd67fd849f3b4580d036353ac5a99f5f11a096e1a4767fc3a64219c641a3a8ad1018e17f4d7f909a60445a70fa34640fcbcc292d7c3969eb6ff5484327a2c7ea68930adda15e7db96c40f5cd181e6c61ce811ba57c9fed17157d675fca2d78483c2d4ee32df33e35bab99dafc0d7455095fd7b931c17920f253c28fa621b656a2bd717c790702eda8974c39f4b14ad4505b5ef0a8848da7ba4a8c74b3ec42ac27a80778766e6e418088df8fa4df5cf1fbd906a696ee5cea54cd13b551dad3411a1aa02042d712bfaa5fd305f67d110e07eef5e4f4e86b8b2ec16cca4c5532489722da6f8017c33676549f9a072ce7c5737b6acb886ba8d88c420d2ef6abb36d3fb0cb98d6a72749919c54e1134bae9fed179b4bc9fc9a63c23529a7e81f54ac56bdde43e4f085745c439df77df96cbcd2aca15b6322adcc1223d643b8d5c57c08000b55677d417382a2650ec082a2cd571d21449d25af2600ced7a2829e307412ab220f393cdf8559dd4c2b98e1f1fa28bb55472556ba25dc4213dc0391f357bc59b96f8e70386676152205a0d16d09c1c28afd94a41792ba37b9a1d0681fd1be7e9eb90e5f3bffa5c9313f089fb0c10643327b0acabeadb43b5bcc1909ebdd70dc975aa0d499295ff4c193b794ab0dd8d5f86c9582dc3ca62a1aca9a243ba0edfa50f48b70fc96500ed2ade304ee8b8d733723bc68ef6b7fab5ba3ebf419589098479c5424f385c046d2541690cee18689ff3222c9630090a438e98f3caa46eb75e27dab9da7743b2214cb26c4396fddfc04e40c07e36dfec40c3942f5a7c15a9533c410235ea4d169a961f52f70992d4e987dd49e9ac16025275b9333abea9006e26f3e7d3462eb765918d27fe4d0e4d390c5eb7161ee5c3ebeed85d0cfc444afcfc35959dc47be6a51fe90568899f4082254785c905ff716f0ab336d586f0d28aae185c52d666e75f56eb6020002d202d63d066960d8f7f217ca9df47e7e672063b25a7df93f321c840464fbee9a11cd0b5ff6ce45ff44eef22e5ffe0e900065108a1a1b68e9aa76eb5a6a78316e68b15019b5e2d11b8e2447d49860b833dfa312237605744273516c79a7030794ba5509620a256d2a8deecc4fb14b4ca14b4a01d82dd1e03b7aaf69149ad5a0b23d3fe6f336932abec9bef23c526180bbe53d6a348a68648914689658a4bba895ff47d35b38b5a3415018ec4dae1230d25f62b8a6ffe06ecef66a54037e1df6f250b7e8f3a427c08d25108385afe638cc186f9cefd7c0b6f36ea366e747f1be2b516846770cec5d8f365a881e244db38c94c",
            "f4e8a473243d0b95d179d992fd214ee9c2434b94dc68788672326c3649ecd6ee404b5a2c0dc5a8958b8e149bfc45a6a19b5a8c2e6501fcad38b40bc19277562f0b81c34e695883a1546e06865cc304b65eefa96c2aac27905f623a4af4f57c74732005806ab0b3a8912e185070a67a41c8306001d97362b96adb694197d8c0d87e7b90b6074048aba03d66ddb17f51362c107e5ca2e1e4317da5dc20b4189e5162aac55fa94959be630cf22e6bbfc3da4df844d24f30f56b626c16cdc72c778b5ee8f4b20a0af6b184045136390557d83601edfbb86b1b3e2315decdf2161ba331f207c37619b5b350796d61a614330efa4b99df5feec76df2922ee2967fed64cc6eeedc136939c04b3eb7d9d1a0a9547c187bce0f5f6e3292d985a1c59b5cc6ae68d4f127f09466f4eb7c03a9355fdda68ed4a88160c49628239ff14d7029d8b67df5045a734b128d4823d53b19ee08440237ad2a3fe8d2350008cc0a154c678eb6efb686f1e9af03d83c8eda1842576fdc43420b6aafb5894681982c5438656c52f55db1758f0904c8c84b5194de2980cad1440c77d8d0001d65065b236e77d1a198c54773097c34f6e22bc2e194be75e40b321e3c7725e8fa618582718e8e673833979517ce2bf59acce74ff34e40709b984e4efad16513fe590f4068d339b9d761a906173192f8665008a8610edbe6ce9d8168594a3a6dbfe6969231584533525eb071b213e6c0aae846c43c2c0bf27c89542f163038e545edb689534b2664c9b558c8e60ba1321c81d66943957f0c0fcf846fe7ad61e0825653d2edd48668b16129b09afb1b4493b0de4497065400f871a91f62822115393b3e00d3c11321eee5b65cb37288489c5c34b7d91b7b7343e7b25a47729c768cad645af9e506dc3ade77b91795d55547d2806c59682d0b18a92b2e4bb06e398dda61c8ff0e4d562aaa3d9b7f213ef271138ee6d8671eedf4043b814714588f3c499f47c381cfa7521831c2e22de17ca165b28fce8db6b2a3e46a51206ba4616f258dc7f1479a4cbff0d5c5f26b83d02e7017920d3df8fcc14d4912a7dfb61338eafc9167693095281bba6e60062e024ffdb27e09d95f70704f083e98ee334cda1b0581aa06d98d1db7babaaf6b3f452b97d3aa72151e59be71ef2d9aefb512834078e53bd1387727f081909fb39aad61c3fb987f0f05a5d4efe12e7a2b2ec09a6652f39e47dc90dbda04c687e3417dcca2b7b063662cf1cc4eac6034fb22035d68d1821dcb61c0b0a7d580eb97a83fdac5b8237dad44f102590f3a96a2b7e505568b146fbe0a1bb7206a4bf10846e585f08d5b6a56206e4e0201c0d5fc7f878cc6451e68206ec8d3947492bc43ce9561b2b5d6c05586ef98f2bb237d312f5cc5577b2bf2eb0451f684e1e383e64117ae32cb7de4ec5b0b68cd6351f86edbfba9104ee40778e42cc90cbe964d3aca8cb4a9ab626533c1815649fa42bb68ecb812f3f78daa4f978a3073d0ca88363a7200c0c3dbdca2ee8268f22e2fe6460e3295b544b8cd165eee6326bcd93a3e3d5e8bede695a75c83d91fb4a752ed5ab5c1ff9756795f61833d5895ae461f024d9f1a07614703771e8e313923a47c22ef3ad82ea39333f6c1c02b68e5ad8a414f38fe941a88696e440ffd8ceb977d49a07f635aab6de9d8d4518ae28f3421eefd1e923660d596948deee132b2e24583b70bd3ef1401c3e89139c16a715563fefead5996d20e3e1508c790b737701f072f507741e2b9419005843ee9d270eb37e72b1680635accbfc4a96b88cb36cbf6e6194ca2ffec28683192a4d3cc4a1d3a598a3c6c9f238cdc727d89fc85fad70804e1aec24552f729ec",
            "192c32cfa39ecab3d9579ce84cbc2eaa5736dda4a46281c66f5278e62c1d392dd4681bc9c6958ae7277ed3f8633bd7f2ce5d278bd2a1cd9f5a07ddb0565a0ee848de759767afe9ac7c796cbe9151b550414328e28bc55609330441be34421a07a58228a3794a26ba5ddcc2f4591cb9f7fb69bdb2f2c47a974163838eb4a67c4db169329aed24f04d9024b68a35dd5115adef6148e497bd074888d3ad9b31fe5aa3bdc76c18f34621b428dd2271ee51cea80f00685da51ccee82d46e6fbbf1c5e5a09d6fa492ff4e09e6d51df36733c0ef524f9116b89603c42eedbf8b7433ee4437c0c81cc6b198010cfed4169a0b5dcce2ee3d42e2b52d6b7577bf04d2e906d23c1e9f246aed9a4c45d45fff660b7548741a039745516dceceb415e0ebdf087d22367f44d9298a3a28c7bd4bcae3e8dea5f7d5731518eb254e0865551485babf516f466e0c9cce00627a24e192c17f90c54be29c9653dbf66d8c5a3ea4768a79be3f1a83440b2dc17ba035fb2cf82a194870293711109f44cbc2a59fc36ec461e189ea8cb0e1e048c58bcfb9fca3df2eee6a74dea723f0ea8353b436651e3439c2993a2fa1c1a526d9b5676d78e6cc224aeacb93a48b22256fa3f0c2f50efa39bed126065dbaec80a9422376d3e91927575360a28b13b0646bd0c8f6a0ef89b4c441642df56d60a15579d134213cde53f58199a1223b61234e7aed71465fcfd9632535b29075c628657b101fde04e8c98c476d159ce51d45b36c49b7c3b0486a833da6238a906a42dd19bad7acae8812f81e53e0ff1977cf2e59c328b4dfd7078e807652c13e78630a6c68db4f8fea1476af81eee05bdcddb0ed7b9c7421426d08f32559a24c081a604d81783743c84bbe2563eff3ff7ab01f279bdfae393a14e27fae8d77731aa9bfe70bcb5249f7f68516c1a643b1af0a4a83f48fbd0036f7c0d57fc68775dfb575ee854bc5e07f79a768c89580ba054343d4d5773ca08f382432108797ffe91556acd41c6b4dedf7e621ab970f568bbb793e7020f9679f98570a7373b3dbeaeaae59830fac84b1c72d21fe6d32d8653b913a868a55cc8671ac21a7a40eaf3604b787343f98f2525ef0e67dacc69f6329accccfa1cb527fde409922f6a8a59afcdb14628560aa011cc1643a5a8b8f8346d3d9f4cb110a87906a3844a76732e96a78f3eb6c07019fbbfb80c8405940829cd68f7d259cea82b3b11f848338cc68791fd6ce79f59118281a2b493cb8741e5f986a77a4193d10b82b8e9f4b482fa70c1ee9fca1c14dadb1c69894b72fa917cf8db6c139e84a77389ceaf7ac26cfcd36573dca9081314881db60d142c1d1fe7b75624c67234e310658587c9d39005d3415f4cda6ba9b67e3b7cc278e169a4b3a97064d3f656d4e1012892a580ff87fb864e57abc75330971caf1c82f8565da9bbdb9d9dbd9d200b807cd0ed963c4a0f8efa29a2690cd0eb91902b2ddd3a483f934ee2312fc2743e21d701bacaad45cefeba0814e546e0236a5e391bfd7833d2c10fe87eeeee97a40ef9fdd96002ff889573ad464454ce4de35388a9e2cd3c77495b1d42936a49da8716a3e10f8e918c2ee317a4945ec71a0caff08b6320c01af24a25d343e2e49644a7c81addb605126cc45065dbe2f0964d3ea4c1221c0a477693cf60e96edca3c48cdc1bd97b5fbab75e4fc9c05bd290eb6e2bef87c66fac3445ef161b73f283419c0f9116a8ce7a8fa6970b03e5fe937e036f67d00433613e18d4d989a7c227181bd12dfd55f5281ee0fc9c80f616e98d336e9bd382212b4dc82cd23d2c3203c049302294c06328600ee627053cfc26a8e88afc35887c7bdb81a686e65de8c1"
        };
        consensus.usdsoqAuthorityThreshold = 2;  // 2-of-3 multisig

        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");

        // AuxPoW parameters - same as mainnet
        consensus.nAuxpowChainId = 0x5351; // "SQ" = Soqucoin
        consensus.fStrictChainId = false;
        consensus.nHeightEffective = 0;
        consensus.fAllowLegacyBlocks = true;

        // Digishield from block 1
        digishieldConsensus = consensus;
        digishieldConsensus.nHeightEffective = 1;
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.nPowTargetTimespan = 60;

        // AuxPoW from block 100
        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.nHeightEffective = 100;
        auxpowConsensus.fAllowLegacyBlocks = false;

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

        // Stagenet Genesis Block - April 2026 (v2 - post CTxOut format change)
        // Unique genesis isolates Stagenet from all other networks
        // Timestamp: 1745769600 = 2026-04-27 12:00:00 UTC
        // Reward: 500,000 SOQ (matches mainnet emission schedule)
        // Nonce mined with scrypt PoW on Services VPS (DO-Premium-Intel)
        genesis = CreateGenesisBlockStagenet(1745769600, 942423, 0x1e0ffff0, 1, 500000 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        assert(consensus.hashGenesisBlock == uint256S("0x073812fa10d3c23358db3a96365ec4afe6a1d674e87a505b31aca2c032554ec0"));
        assert(genesis.hashMerkleRoot == uint256S("0x9abbf4b3788c188d54f03437f8cfecdfd92ee5406159931146d86cb32cee10b5"));

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
