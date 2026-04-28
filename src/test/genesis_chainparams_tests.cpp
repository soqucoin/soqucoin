// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-INFRA-020: Genesis block and chainparams validation tests
// Pre-mainnet checklist items:
//   - Genesis PoW verification for all networks
//   - BIP34Height > 16 assertion (prevents OP_N encoding mismatch)
//   - Serialization consistency (genesis hash stability)

#include "chainparams.h"
#include "consensus/consensus.h"
#include "soqucoin.h"
#include "primitives/block.h"
#include "uint256.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(genesis_chainparams_tests, BasicTestingSetup)

// ============================================================================
// Genesis PoW Verification Tests
//
// These tests verify that the hardcoded genesis nonces produce valid
// proof-of-work hashes for each network. This catches the critical bug
// from Stagenet Issue #7: GetHash() vs GetPoWHash() confusion.
//
// If ANY of these tests fail after a serialization change, ALL genesis
// nonces must be re-mined before release.
// ============================================================================

BOOST_AUTO_TEST_CASE(regtest_genesis_pow_valid)
{
    SelectParams(CBaseChainParams::REGTEST);
    const CChainParams& params = Params();
    const CBlock& genesis = params.GenesisBlock();
    const Consensus::Params& consensus = params.GetConsensus(0);

    // Genesis hash matches hardcoded value
    BOOST_CHECK_EQUAL(genesis.GetHash().ToString(),
                      consensus.hashGenesisBlock.ToString());

    // PoW is valid (uses scrypt via GetPoWHash)
    BOOST_CHECK(CheckAuxPowProofOfWork(genesis, consensus));
}

BOOST_AUTO_TEST_CASE(stagenet_genesis_pow_valid)
{
    SelectParams(CBaseChainParams::STAGENET);
    const CChainParams& params = Params();
    const CBlock& genesis = params.GenesisBlock();
    const Consensus::Params& consensus = params.GetConsensus(0);

    // Genesis hash matches hardcoded value
    BOOST_CHECK_EQUAL(genesis.GetHash().ToString(),
                      consensus.hashGenesisBlock.ToString());

    // PoW is valid (uses scrypt via GetPoWHash — Issue #7 regression test)
    BOOST_CHECK(CheckAuxPowProofOfWork(genesis, consensus));
}

// NOTE: Mainnet and testnet3 genesis nonces are not yet final.
// These tests should be enabled once the serialization format is frozen
// and genesis nonces are re-mined.
//
// BOOST_AUTO_TEST_CASE(mainnet_genesis_pow_valid)
// BOOST_AUTO_TEST_CASE(testnet3_genesis_pow_valid)

// ============================================================================
// Genesis Block Consistency Tests
//
// Verify that genesis block properties are sane and consistent.
// ============================================================================

BOOST_AUTO_TEST_CASE(regtest_genesis_merkle_root_consistent)
{
    SelectParams(CBaseChainParams::REGTEST);
    const CBlock& genesis = Params().GenesisBlock();

    // Genesis should have exactly 1 transaction (coinbase)
    BOOST_CHECK_EQUAL(genesis.vtx.size(), 1u);

    // Merkle root should match the single coinbase TX hash
    BOOST_CHECK_EQUAL(genesis.hashMerkleRoot.ToString(),
                      genesis.vtx[0]->GetHash().ToString());
}

BOOST_AUTO_TEST_CASE(stagenet_genesis_merkle_root_consistent)
{
    SelectParams(CBaseChainParams::STAGENET);
    const CBlock& genesis = Params().GenesisBlock();

    // Genesis should have exactly 1 transaction (coinbase)
    BOOST_CHECK_EQUAL(genesis.vtx.size(), 1u);

    // Merkle root should match the single coinbase TX hash
    BOOST_CHECK_EQUAL(genesis.hashMerkleRoot.ToString(),
                      genesis.vtx[0]->GetHash().ToString());
}

BOOST_AUTO_TEST_CASE(genesis_coinbase_outputs_have_correct_fields)
{
    // Verify that CTxOut fields (nVisibility, nAssetType) are set correctly
    // in genesis coinbase outputs. This catches serialization regressions.
    SelectParams(CBaseChainParams::STAGENET);
    const CBlock& genesis = Params().GenesisBlock();
    const CTransaction& coinbase = *genesis.vtx[0];

    BOOST_CHECK(coinbase.vout.size() >= 1);
    for (const auto& out : coinbase.vout) {
        // Genesis coinbase outputs must be transparent native SOQ
        BOOST_CHECK_EQUAL(out.nVisibility, 0x00);
        BOOST_CHECK_EQUAL(out.nAssetType, 0x00);
    }
}

// ============================================================================
// BIP34Height Safety Tests
//
// BIP34 requires the block height to be serialized in the coinbase scriptSig.
// Heights <= 16 use OP_N opcodes (OP_1 through OP_16), but heights > 16 use
// CScriptNum push encoding. If BIP34Height is <= 16, there's an encoding
// ambiguity that can cause consensus splits.
//
// Reference: Stagenet Issues Log, derived from Issue #15
// ============================================================================

BOOST_AUTO_TEST_CASE(bip34_height_safety_regtest)
{
    SelectParams(CBaseChainParams::REGTEST);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // Regtest: BIP34 is set very high (100000000) to allow v1 blocks in tests
    // This is intentionally above 16, so the check passes trivially
    BOOST_CHECK_GT(consensus.BIP34Height, 16);
}

BOOST_AUTO_TEST_CASE(bip34_height_safety_stagenet)
{
    SelectParams(CBaseChainParams::STAGENET);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // Stagenet: Must be > 16 to avoid OP_N mismatch
    BOOST_CHECK_GT(consensus.BIP34Height, 16);
}

BOOST_AUTO_TEST_CASE(bip34_height_safety_mainnet)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // Mainnet: Must be > 16 — this is the most critical assertion
    BOOST_CHECK_GT(consensus.BIP34Height, 16);
}

BOOST_AUTO_TEST_CASE(bip34_height_safety_testnet3)
{
    SelectParams(CBaseChainParams::TESTNET);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // Testnet3: Must be > 16
    BOOST_CHECK_GT(consensus.BIP34Height, 16);
}

// ============================================================================
// BIP9 Deployment Sanity Tests
//
// Verify that critical deployments are configured correctly on each network.
// ============================================================================

BOOST_AUTO_TEST_CASE(stagenet_critical_deployments_active)
{
    SelectParams(CBaseChainParams::STAGENET);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // PAT (bit 3) — must be ALWAYS_ACTIVE
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);

    // LatticeFold (bit 4) — must be ALWAYS_ACTIVE
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);

    // NOTE: Lattice-BP++ (bit 5) and USDSOQ (bit 6) are NOT ALWAYS_ACTIVE on
    // stagenet — they mirror mainnet where they await Halborn audit + BIP9 signaling.
    // Testnet3 has them ALWAYS_ACTIVE for integration testing.
    // If you need to test confidential TXs or USDSOQ opcodes on stagenet,
    // these must be changed to ALWAYS_ACTIVE here.
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].nStartTime, 0);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime, 0);
}

BOOST_AUTO_TEST_CASE(regtest_critical_deployments_active)
{
    SelectParams(CBaseChainParams::REGTEST);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // All 4 critical deployments should be ALWAYS_ACTIVE on regtest
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
}

// ============================================================================
// Subsidy Calculation Tests
//
// Verify the halving schedule matches documented tokenomics.
// ============================================================================

BOOST_AUTO_TEST_CASE(subsidy_halving_schedule)
{
    SelectParams(CBaseChainParams::STAGENET);
    const Consensus::Params& consensus = Params().GetConsensus(0);
    uint256 dummyHash;
    dummyHash.SetNull();

    // Block 0: 500,000 SOQ
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(0, consensus, dummyHash), 500000 * COIN);
    // After first halving: 250,000 SOQ
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(consensus.nSubsidyHalvingInterval, consensus, dummyHash), 250000 * COIN);
    // After second halving: 125,000 SOQ
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(2 * consensus.nSubsidyHalvingInterval, consensus, dummyHash), 125000 * COIN);
    // After sixth halving: perpetual 10,000 SOQ
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(6 * consensus.nSubsidyHalvingInterval, consensus, dummyHash), 10000 * COIN);
    // Way past sixth halving: still 10,000 SOQ (perpetual inflation)
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(100 * consensus.nSubsidyHalvingInterval, consensus, dummyHash), 10000 * COIN);
}

BOOST_AUTO_TEST_SUITE_END()
