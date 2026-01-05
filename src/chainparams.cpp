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

#include "arith_uint256.h" // For genesis mining
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

        // LatticeFold+ activation - January 2026 (future soft fork)
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime = 1737331200; // Jan 20 2026
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout = 1768867200;   // Jan 20 2027


        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000e993d2aa86cf246a49b"); // 5,050,000

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");
        consensus.dilithiumOnlyHeight = 0;
        consensus.dilithiumOnlyHeight = 0;
        consensus.nLatticeFoldActivationHeight = 2147483647; // INT_MAX for now

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

        // Blocks 371337+ are AuxPoW
        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.nHeightEffective = 371337;
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

        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        assert(consensus.hashGenesisBlock == uint256S("0x1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691"));
        assert(genesis.hashMerkleRoot == uint256S("0x5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69"));

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

        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime = 1737331200; // Jan 20 2026
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout = 1768867200;   // Jan 20 2027

        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime = 1737331200; // Jan 20 2026
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout = 1768867200;   // Jan 20 2027

        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // LatticeFold+ activation - January 2026 (future soft fork)
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime = 1737331200; // Jan 20 2026
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout = 1768867200;   // Jan 20 2027

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
        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        minDifficultyConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        assert(consensus.hashGenesisBlock == uint256S("0xcde63e00ef4c268af3bb351e2f7c9f4a2cbb21ec9f3d989e2c6594df810b7594"));
        assert(genesis.hashMerkleRoot == uint256S("0x5a23cb4c71feb8767bb07cdedc1dd316ac648ec35416222027d0d2d8e0287415"));

        // Clear all Dogecoin seeds - Soqucoin testnet is isolated
        vSeeds.clear();
        // Soqucoin-only seed nodes (add more as deployed)
        // vSeeds.push_back(CDNSSeedData("soqu.org", "seed.soqu.org"));

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

        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime = 1737331200; // Jan 20 2026
        consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nTimeout = 1768867200;   // Jan 20 2027


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
        assert(consensus.hashGenesisBlock == uint256S("0x3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5"));
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
};
static CRegTestParams regTestParams;

/**
 * Stagenet - Mainnet rehearsal network
 * Mirrors mainnet staged activation schedule:
 * - BP++ activates at height 50,000
 * - LatticeFold+ activates at height 100,000
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
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 4 * 60 * 60; // 4 hours
        consensus.nPowTargetSpacing = 60;           // 1 minute
        consensus.fDigishieldDifficultyCalculation = true;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowAllowDigishieldMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512;
        consensus.nMinerConfirmationWindow = 2016;
        consensus.fSimplifiedRewards = true;
        consensus.nCoinbaseMaturity = 30;

        // Dilithium only from genesis
        consensus.dilithiumOnlyHeight = 0;

        // Mainnet-mirrored staged activation\n        // BP++ activation is via BIP9 softfork\n        consensus.nLatticeFoldActivationHeight = 100000; // LatticeFold+ at height 100k (same as mainnet)

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

        // Stagenet Genesis Block - January 2026
        // Unique genesis isolates Stagenet from all other networks
        // Genesis nonce will be mined on first run
        genesis = CreateGenesisBlockTestnet3(1736107200, 2583191, 0x1e0ffff0, 1, 500000 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;

        vSeeds.clear();
        // vSeeds.push_back(CDNSSeedData("soqu.org", "stagenet.soqu.org"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 125); // s prefix
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 100); // g prefix
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 253);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xcf).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds.clear();

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
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
