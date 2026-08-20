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

#include <map>
#include <string>

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
    // Phase 4: Verify genesis coinbase outputs are transparent native SOQ
    // via structural predicates (nVisibility/nAssetType bytes were removed).
    SelectParams(CBaseChainParams::STAGENET);
    const CBlock& genesis = Params().GenesisBlock();
    const CTransaction& coinbase = *genesis.vtx[0];

    BOOST_CHECK(coinbase.vout.size() >= 1);
    for (const auto& out : coinbase.vout) {
        // Genesis coinbase outputs must be transparent native SOQ
        BOOST_CHECK(out.IsNativeSOQ());
        BOOST_CHECK(!out.IsConfidential());
        BOOST_CHECK(!out.IsUSDSOQ());
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

    // SoquObscura (bit 5) — WITHDRAWN 2026-08-17, must NOT be active. Its range
    // verifier accepts an all-zero witness carrying a correct Fiat-Shamir seed.
    // Full dormancy assertions live in test/soquobscura_withdrawal_tests.cpp.
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nStartTime, 0);
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(
        0, consensus, Consensus::DEPLOYMENT_SOQUOBSCURA));

    // USDSOQ (bit 6) — ALWAYS_ACTIVE on stagenet (Apr 28, 2026 activation)
    // Enables mint/burn/freeze testing. Mainnet remains NOT_ACTIVE pending audit.
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
}

BOOST_AUTO_TEST_CASE(regtest_critical_deployments_active)
{
    SelectParams(CBaseChainParams::REGTEST);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // PAT, LatticeFold and USDSOQ stay ALWAYS_ACTIVE on regtest.
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_CHECKPATAGG].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);

    // SoquObscura — WITHDRAWN 2026-08-17, must NOT be active. Regtest is included
    // in the withdrawal deliberately: leaving it active would keep every
    // functional test running against a verifier known to accept forged proofs.
    // Full dormancy assertions live in test/soquobscura_withdrawal_tests.cpp.
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA].nStartTime, 0);
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(
        0, consensus, Consensus::DEPLOYMENT_SOQUOBSCURA));
}

// g7c regression guard: the BASE witness framework (SegWit + CSV) must be
// active from genesis on MAINNET. If these ever revert to the inherited
// Bitcoin/Dogecoin BIP9 windows (real timestamps / SegWit nTimeout=0), they
// resolve to THRESHOLD_FAILED on a post-2017 genesis chain and every witness
// program (v0-v7: all Dilithium/PAT/LatticeFold outputs) becomes
// anyone-can-spend. See DL-G7C-SEGWIT-CSV-GENESIS-ACTIVATION.md.
BOOST_AUTO_TEST_CASE(mainnet_witness_framework_active_from_genesis)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // SegWit must be ALWAYS_ACTIVE (nStartTime == -1, nTimeout == NO_TIMEOUT)
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout,
                      Consensus::BIP9Deployment::NO_TIMEOUT);

    // CSV must be ALWAYS_ACTIVE (BIP68/112/113 — L2SOQ force-close depends on it)
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout,
                      Consensus::BIP9Deployment::NO_TIMEOUT);

    // Belt-and-suspenders: the SegWit nTimeout must never be 0 (the specific
    // "Disabled" value that also suppresses the coinbase witness commitment).
    BOOST_CHECK(consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0);
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

    // 47B Moderate emission (locked 2026-06-28, bead c61): 100K launch reward,
    // 4 halvings at nSubsidyHalvingInterval, then a perpetual 2,500 SOQ tail.
    // Block 0 (epoch 0): 100,000 SOQ
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(0, consensus, dummyHash), 100000 * COIN);
    // After first halving: 50,000 SOQ
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(consensus.nSubsidyHalvingInterval, consensus, dummyHash), 50000 * COIN);
    // After second halving: 25,000 SOQ
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(2 * consensus.nSubsidyHalvingInterval, consensus, dummyHash), 25000 * COIN);
    // After third halving (final head epoch): 12,500 SOQ
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(3 * consensus.nSubsidyHalvingInterval, consensus, dummyHash), 12500 * COIN);
    // Fourth halving onward: perpetual 2,500 SOQ tail
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(4 * consensus.nSubsidyHalvingInterval, consensus, dummyHash), 2500 * COIN);
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(6 * consensus.nSubsidyHalvingInterval, consensus, dummyHash), 2500 * COIN);
    // Way past the tail transition: still 2,500 SOQ (perpetual inflation)
    BOOST_CHECK_EQUAL(GetSoqucoinBlockSubsidy(100 * consensus.nSubsidyHalvingInterval, consensus, dummyHash), 2500 * COIN);
}

// ============================================================================
// p96 / Option D — flag-day (height-gated) soft-fork activation
// ============================================================================

// The height-gated deployments that moved off BIP9 signaling (bits 5-13).
static const Consensus::DeploymentPos P96_FLAGDAY_DEPLOYMENTS[] = {
    Consensus::DEPLOYMENT_SOQUOBSCURA,
    Consensus::DEPLOYMENT_USDSOQ,
    Consensus::DEPLOYMENT_CTV,
    Consensus::DEPLOYMENT_APO,
    Consensus::DEPLOYMENT_CSFS,
    Consensus::DEPLOYMENT_P2WSH_DILITHIUM,
    Consensus::DEPLOYMENT_UTXO_COST,
    Consensus::DEPLOYMENT_DILITHIUM_KEYHASH,
    Consensus::DEPLOYMENT_V6_CONTROLFLOW,
    // BTCSOQ is height-gated exactly like the rest (mainnet NOT_SCHEDULED,
    // test networks 0) and was simply missing from this list, so the mainnet
    // dormancy assertion below did not cover the Bitcoin-backed asset.
    Consensus::DEPLOYMENT_BTCSOQ,
};

BOOST_AUTO_TEST_CASE(p96_deployment_active_predicate)
{
    Consensus::Params p;  // vDeployments default-constructed (nActivationHeight = NO_HEIGHT_ACTIVATION)
    const Consensus::DeploymentPos pos = Consensus::DEPLOYMENT_USDSOQ;

    // NO_HEIGHT_ACTIVATION (not height-gated) → never active via this predicate,
    // even at absurd heights. Such deployments must be queried via BIP9 instead.
    p.vDeployments[pos].nActivationHeight = Consensus::BIP9Deployment::NO_HEIGHT_ACTIVATION;
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(0, p, pos));
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(1000000, p, pos));

    // NOT_SCHEDULED → dormant at every reachable height (ships-off on mainnet).
    p.vDeployments[pos].nActivationHeight = Consensus::BIP9Deployment::NOT_SCHEDULED;
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(0, p, pos));
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(1000000000, p, pos));

    // A concrete future height H: inactive below H, active at/above H (flag day).
    p.vDeployments[pos].nActivationHeight = 500000;
    BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(499999, p, pos));
    BOOST_CHECK(Consensus::DeploymentActiveAtHeight(500000, p, pos));   // first enforcing block
    BOOST_CHECK(Consensus::DeploymentActiveAtHeight(500001, p, pos));

    // Height 0 → active from genesis (the test-network configuration).
    p.vDeployments[pos].nActivationHeight = 0;
    BOOST_CHECK(Consensus::DeploymentActiveAtHeight(0, p, pos));
    BOOST_CHECK(Consensus::DeploymentActiveAtHeight(1, p, pos));
}

BOOST_AUTO_TEST_CASE(p96_mainnet_ships_dormant)
{
    // Every flag-day soft-fork must be dormant on mainnet at genesis and stay
    // dormant until a coordinated release sets a real height. Prevents an
    // accidental genesis-active PQ/covenant/economic rule on mainnet.
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensus = Params().GetConsensus(0);
    for (const auto pos : P96_FLAGDAY_DEPLOYMENTS) {
        BOOST_CHECK_EQUAL(consensus.vDeployments[pos].nActivationHeight,
                          Consensus::BIP9Deployment::NOT_SCHEDULED);
        BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(0, consensus, pos));
        BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(1000000, consensus, pos));
    }
}

BOOST_AUTO_TEST_CASE(p96_testnets_active_from_genesis)
{
    // Regtest and stagenet must keep the flag-day features active from genesis
    // (height 0), preserving the prior ALWAYS_ACTIVE test behavior — and the
    // live stagenet's historical blocks must validate identically.
    //
    // ⛔ ONE DELIBERATE EXCEPTION: DEPLOYMENT_SOQUOBSCURA was WITHDRAWN from all
    // networks on 2026-08-17 because its range verifier accepts an all-zero
    // witness carrying a correct Fiat-Shamir seed, so a confidential output
    // proves nothing about its amount. Keeping it active here would keep every
    // functional test running against a verifier known to accept forged proofs.
    // Its dormancy is asserted positively — and much more thoroughly — in
    // test/soquobscura_withdrawal_tests.cpp, so nothing is lost by skipping it.
    // ⚠️ Do NOT remove it from P96_FLAGDAY_DEPLOYMENTS: that array still guards
    // the mainnet NOT_SCHEDULED assertion above, which SoquObscura must satisfy.
    for (const std::string& net : {CBaseChainParams::REGTEST, CBaseChainParams::STAGENET}) {
        SelectParams(net);
        const Consensus::Params& consensus = Params().GetConsensus(0);
        for (const auto pos : P96_FLAGDAY_DEPLOYMENTS) {
            if (pos == Consensus::DEPLOYMENT_SOQUOBSCURA) continue;  // withdrawn, see above
            BOOST_CHECK_EQUAL(consensus.vDeployments[pos].nActivationHeight, 0);
            BOOST_CHECK(Consensus::DeploymentActiveAtHeight(0, consensus, pos));
        }
    }
    SelectParams(CBaseChainParams::MAIN);  // restore default for later tests
}

// ============================================================================
// F8 (bead v7xm): the activation posture must hold at EVERY height, not just 0.
//
// The two tests above read GetConsensus(0), which returns the BASE consensus
// struct. That is not the struct most blocks are validated against. Every
// network assembles a height-indexed tree of Consensus::Params
// (consensus / digishieldConsensus / auxpowConsensus) and GetConsensus(nHeight)
// returns whichever tier covers that height — on regtest the cutovers are 10 and
// 20, on stagenet 1 and 100. The constructors copy the base struct AFTER setting
// the deployment fields, so the tiers agree today; nothing enforces that they
// keep agreeing, and a per-tier divergence would mean a deployment that is
// dormant at genesis and live at height 20, or the reverse.
//
// This is not hypothetical. A regtest activation lever added on 2026-08-20
// initially wrote only the base struct and was silently inert for every block a
// chain fixture mines. The same shape sits in UpdateMaxReorgDepth, which writes
// consensus and digishieldConsensus but not auxpowConsensus (bead tofg).
// ============================================================================
BOOST_AUTO_TEST_CASE(f8_deployment_posture_is_uniform_across_consensus_tiers)
{
    // Heights chosen to straddle every tier cutover on every network.
    const int kProbeHeights[] = {0, 1, 2, 9, 10, 11, 19, 20, 21, 99, 100, 101, 1000, 1000000};

    for (const std::string& net : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                   CBaseChainParams::REGTEST, CBaseChainParams::STAGENET}) {
        SelectParams(net);
        for (int pos = 0; pos < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; pos++) {
            const auto d = static_cast<Consensus::DeploymentPos>(pos);
            const Consensus::BIP9Deployment& base = Params().GetConsensus(0).vDeployments[d];
            for (int h : kProbeHeights) {
                const Consensus::BIP9Deployment& tier = Params().GetConsensus(h).vDeployments[d];
                BOOST_CHECK_MESSAGE(tier.nActivationHeight == base.nActivationHeight,
                    net + ": deployment " + std::to_string(pos) + " has nActivationHeight " +
                    std::to_string(tier.nActivationHeight) + " at height " + std::to_string(h) +
                    " but " + std::to_string(base.nActivationHeight) + " in the base struct — "
                    "the consensus tiers have diverged");
                BOOST_CHECK_MESSAGE(tier.bit == base.bit,
                    net + ": deployment " + std::to_string(pos) + " changes version bit across tiers");
                BOOST_CHECK_MESSAGE(tier.nStartTime == base.nStartTime &&
                                    tier.nTimeout == base.nTimeout,
                    net + ": deployment " + std::to_string(pos) + " changes its BIP9 window across tiers");
            }
        }
    }
    SelectParams(CBaseChainParams::MAIN);
}

// A height-gated deployment ignores nStartTime/nTimeout entirely, so a
// deployment carrying BOTH an nActivationHeight and a real BIP9 window is a
// statement of intent the code will not honour. Reject the combination outright
// rather than trusting anyone to remember the rule. The inert values (0/0 for
// "never" and ALWAYS_ACTIVE/NO_TIMEOUT for the pre-flag-day form) are allowed
// because they are what the existing configs use to mean "the BIP9 fields are
// not the mechanism here".
BOOST_AUTO_TEST_CASE(f8_no_deployment_relies_on_a_bip9_window_it_cannot_use)
{
    for (const std::string& net : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                   CBaseChainParams::REGTEST, CBaseChainParams::STAGENET}) {
        SelectParams(net);
        const Consensus::Params& c = Params().GetConsensus(0);
        for (int pos = 0; pos < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; pos++) {
            const Consensus::BIP9Deployment& d = c.vDeployments[static_cast<Consensus::DeploymentPos>(pos)];
            if (d.nActivationHeight == Consensus::BIP9Deployment::NO_HEIGHT_ACTIVATION) continue;

            const bool inertWindow =
                (d.nStartTime == 0 && d.nTimeout == 0) ||
                (d.nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE &&
                 d.nTimeout == Consensus::BIP9Deployment::NO_TIMEOUT);
            BOOST_CHECK_MESSAGE(inertWindow,
                net + ": deployment " + std::to_string(pos) + " is height-gated (nActivationHeight=" +
                std::to_string(d.nActivationHeight) + ") yet carries a live BIP9 window. "
                "DeploymentActiveAtHeight never reads nStartTime/nTimeout, so that window is a no-op "
                "and whoever set it believed something false about how this deployment activates.");
        }
    }
    SelectParams(CBaseChainParams::MAIN);
}

// Two deployments sharing a version bit means signalling for one is signalling
// for the other. Harmless while both are inert; a chain split if either is ever
// scheduled. TESTDUMMY is excluded because it is a test fixture rather than a
// feature, and it currently collides with LATTICEFOLD on bit 28 (bead nv7q) —
// excluding it here keeps this test honest about FEATURE bits without encoding
// that known overlap as acceptable.
BOOST_AUTO_TEST_CASE(f8_feature_deployments_do_not_share_version_bits)
{
    for (const std::string& net : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                   CBaseChainParams::REGTEST, CBaseChainParams::STAGENET}) {
        SelectParams(net);
        const Consensus::Params& c = Params().GetConsensus(0);
        std::map<int, int> bitOwner;   // bit -> deployment index
        for (int pos = 0; pos < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; pos++) {
            if (pos == Consensus::DEPLOYMENT_TESTDUMMY) continue;
            const int bit = c.vDeployments[static_cast<Consensus::DeploymentPos>(pos)].bit;
            auto it = bitOwner.find(bit);
            BOOST_CHECK_MESSAGE(it == bitOwner.end(),
                net + ": deployments " + std::to_string(it == bitOwner.end() ? -1 : it->second) +
                " and " + std::to_string(pos) + " both claim version bit " + std::to_string(bit));
            bitOwner[bit] = pos;
        }
    }
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_SUITE_END()
