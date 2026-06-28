// Copyright (c) 2015-2022 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "arith_uint256.h"
#include "chainparams.h"
#include "soqucoin.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(soqucoin_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(subsidy_first_100k_test)
{
    const CChainParams& mainParams = Params(CBaseChainParams::MAIN);
    CAmount nSum = 0;
    arith_uint256 prevHash = UintToArith256(uint256S("0"));

    for (int nHeight = 0; nHeight <= 100000; nHeight++) {
        const Consensus::Params& params = mainParams.GetConsensus(nHeight);
        CAmount nSubsidy = GetSoqucoinBlockSubsidy(nHeight, params, ArithToUint256(prevHash));
        BOOST_CHECK(MoneyRange(nSubsidy));
        BOOST_CHECK(nSubsidy <= 100000 * COIN);
        nSum += nSubsidy;
        // Use nSubsidy to give us some variation in previous block hash, without requiring full block templates
        prevHash += nSubsidy;
    }

    // 47B Moderate schedule (bead c61): heights 0..100000 are all in epoch 0
    // (< 250,000-block halving interval), each minting the 100,000 SOQ launch reward.
    // 100,001 blocks × 100,000 SOQ
    const CAmount expected = (CAmount)10000100000LL * COIN;
    BOOST_CHECK_EQUAL(expected, nSum);
}

BOOST_AUTO_TEST_CASE(subsidy_100k_145k_test)
{
    const CChainParams& mainParams = Params(CBaseChainParams::MAIN);
    CAmount nSum = 0;
    arith_uint256 prevHash = UintToArith256(uint256S("0"));

    for (int nHeight = 100000; nHeight <= 145000; nHeight++) {
        const Consensus::Params& params = mainParams.GetConsensus(nHeight);
        CAmount nSubsidy = GetSoqucoinBlockSubsidy(nHeight, params, ArithToUint256(prevHash));
        BOOST_CHECK(MoneyRange(nSubsidy));
        BOOST_CHECK(nSubsidy <= 100000 * COIN);
        nSum += nSubsidy;
        // Use nSubsidy to give us some variation in previous block hash, without requiring full block templates
        prevHash += nSubsidy;
    }

    // 47B Moderate schedule (bead c61): heights 100000..145000 are still in epoch 0
    // (< 250,000-block interval), each minting 100,000 SOQ.
    // 45,001 blocks × 100,000 SOQ
    const CAmount expected = (CAmount)4500100000LL * COIN;
    BOOST_CHECK_EQUAL(expected, nSum);
}

// Check the simplified rewards after block 145,000
BOOST_AUTO_TEST_CASE(subsidy_post_145k_test)
{
    const CChainParams& mainParams = Params(CBaseChainParams::MAIN);
    const uint256 prevHash = uint256S("0");

    // 47B Moderate schedule (bead c61): reward = (100000 >> halvings) across the 4
    // head epochs, then a perpetual 2,500 SOQ tail from 4 × interval (height 1,000,000).
    for (int nHeight = 145000; nHeight < 1100000; nHeight++) {
        const Consensus::Params& params = mainParams.GetConsensus(nHeight);
        const int interval = params.nSubsidyHalvingInterval;
        CAmount nSubsidy = GetSoqucoinBlockSubsidy(nHeight, params, prevHash);
        CAmount nExpectedSubsidy = (nHeight < 4 * interval)
            ? (100000 >> (nHeight / interval)) * COIN
            : 2500 * COIN;
        BOOST_CHECK(MoneyRange(nSubsidy));
        BOOST_CHECK_EQUAL(nSubsidy, nExpectedSubsidy);
    }

    // Tail is constant 2,500 SOQ from the 4th halving (height 1,000,000) onward.
    const int interval = mainParams.GetConsensus(0).nSubsidyHalvingInterval;
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(4 * interval, mainParams.GetConsensus(4 * interval), prevHash), 2500 * COIN);
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(6 * interval, mainParams.GetConsensus(6 * interval), prevHash), 2500 * COIN);
}

BOOST_AUTO_TEST_CASE(get_next_work_difficulty_limit)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(0);

    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1386474927; // Block # 1
    
    pindexLast.nHeight = 239;
    pindexLast.nTime = 1386475638; // Block #239
    pindexLast.nBits = 0x1e0ffff0;
    BOOST_CHECK_EQUAL(CalculateSoqucoinNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1e00ffff);
}

BOOST_AUTO_TEST_CASE(get_next_work_pre_digishield)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(0);
    
    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1386942008; // Block 9359

    pindexLast.nHeight = 9599;
    pindexLast.nTime = 1386954113;
    pindexLast.nBits = 0x1c1a1206;
    BOOST_CHECK_EQUAL(CalculateSoqucoinNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1c15ea59);
}

BOOST_AUTO_TEST_CASE(get_next_work_digishield)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);
    
    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1395094427;

    // First hard-fork at 145,000, which applies to block 145,001 onwards
    pindexLast.nHeight = 145000;
    pindexLast.nTime = 1395094679;
    pindexLast.nBits = 0x1b499dfd;
    BOOST_CHECK_EQUAL(CalculateSoqucoinNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b671062);
}

BOOST_AUTO_TEST_CASE(get_next_work_digishield_modulated_upper)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);
    
    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1395100835;

    // Test the upper bound on modulated time using mainnet block #145,107
    pindexLast.nHeight = 145107;
    pindexLast.nTime = 1395101360;
    pindexLast.nBits = 0x1b3439cd;
    BOOST_CHECK_EQUAL(CalculateSoqucoinNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b4e56b3);
}

BOOST_AUTO_TEST_CASE(get_next_work_digishield_modulated_lower)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);
    
    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1395380517;

    // Test the lower bound on modulated time using mainnet block #149,423
    pindexLast.nHeight = 149423;
    pindexLast.nTime = 1395380447;
    pindexLast.nBits = 0x1b446f21;
    BOOST_CHECK_EQUAL(CalculateSoqucoinNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b335358);
}

BOOST_AUTO_TEST_CASE(get_next_work_digishield_rounding)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);
    
    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1395094679;

    // Test case for correct rounding of modulated time - this depends on
    // handling of integer division, and is not obvious from the code
    pindexLast.nHeight = 145001;
    pindexLast.nTime = 1395094727;
    pindexLast.nBits = 0x1b671062;
    BOOST_CHECK_EQUAL(CalculateSoqucoinNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b6558a4);
}

BOOST_AUTO_TEST_CASE(hardfork_parameters)
{
    SelectParams(CBaseChainParams::MAIN);

    // Block 0: genesis — pre-DigiShield, pre-AuxPoW
    const Consensus::Params& genesisParams = Params().GetConsensus(0);
    BOOST_CHECK_EQUAL(genesisParams.nPowTargetTimespan, 14400);
    BOOST_CHECK_EQUAL(genesisParams.fAllowLegacyBlocks, true);
    BOOST_CHECK_EQUAL(genesisParams.fDigishieldDifficultyCalculation, false);

    // Block 1: DigiShield activates (per-block difficulty retarget)
    const Consensus::Params& digishieldParams = Params().GetConsensus(1);
    BOOST_CHECK_EQUAL(digishieldParams.nPowTargetTimespan, 60);
    BOOST_CHECK_EQUAL(digishieldParams.fAllowLegacyBlocks, true);
    BOOST_CHECK_EQUAL(digishieldParams.fDigishieldDifficultyCalculation, true);

    // Block 999: still DigiShield, no AuxPoW yet
    const Consensus::Params& preAuxpowParams = Params().GetConsensus(999);
    BOOST_CHECK_EQUAL(preAuxpowParams.nPowTargetTimespan, 60);
    BOOST_CHECK_EQUAL(preAuxpowParams.fDigishieldDifficultyCalculation, true);

    // AuxPoW is valid from genesis on mainnet — there is NO activation window.
    // nAuxpowStartHeight=0 (chainparams.cpp CMainParams "AuxPoW from genesis",
    // DL-MAINNET-DIFFICULTY-TRANSITION); the validation gate rejects an AuxPoW block
    // only when nHeight < nAuxpowStartHeight, which is never true at 0.
    BOOST_CHECK_EQUAL(Params().GetConsensus(0).nAuxpowStartHeight, 0);

    // Block 1000: still the single merged DigiShield+AuxPoW tier that began at block 1
    // (nHeightEffective=1) — NOT a new tier. There is no block-1000 milestone: the prior
    // "Vanguard Window ends at 1000" assertion was fiction. The only Vanguard Window in
    // the project is stagenet's solo-first-100-blocks (nAuxpowStartHeight=100); mainnet
    // launches AuxPoW from genesis with SOQUPOOL hashrate behind it.
    const Consensus::Params& auxpowParams = Params().GetConsensus(1000);
    BOOST_CHECK_EQUAL(auxpowParams.nHeightEffective, 1);
    BOOST_CHECK_EQUAL(auxpowParams.nPowTargetTimespan, 60);
    BOOST_CHECK_EQUAL(auxpowParams.fAllowLegacyBlocks, true);
    BOOST_CHECK_EQUAL(auxpowParams.fDigishieldDifficultyCalculation, true);

    // Far future: all params stable
    const Consensus::Params& futureParams = Params().GetConsensus(700000);
    BOOST_CHECK_EQUAL(futureParams.nPowTargetTimespan, 60);
    BOOST_CHECK_EQUAL(futureParams.fAllowLegacyBlocks, true);
    BOOST_CHECK_EQUAL(futureParams.fDigishieldDifficultyCalculation, true);
}

BOOST_AUTO_TEST_SUITE_END()
