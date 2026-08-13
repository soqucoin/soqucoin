// Copyright (c) 2025-2026 The Soqucoin Core developers
// Distributed under the MIT software license
//
// LatticeFold verifier tests — updated for SOQ-A005 redesign.
// Tests the new API with external binding (sighash, pubkey_hash, dilithium_sigs).

#include "crypto/latticefold/verifier.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "consensus/params.h"
#include "policy/policy.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(latticefold_tests, BasicTestingSetup)

// Helper: create dummy external binding parameters
static uint256 MakeDummySighash()
{
    uint256 h;
    memset(h.begin(), 0xAA, 32);
    return h;
}

static std::array<uint8_t, 32> MakeDummyPubkeyHash()
{
    std::array<uint8_t, 32> h;
    h.fill(0xBB);
    return h;
}

static std::vector<valtype> MakeDummySigs(int n = 1)
{
    std::vector<valtype> sigs;
    for (int i = 0; i < n; ++i) {
        valtype sig(2420, static_cast<uint8_t>(i + 1)); // Dilithium-44 sig size
        sigs.push_back(sig);
    }
    return sigs;
}

BOOST_AUTO_TEST_CASE(proof_parsing_bounds_v2)
{
    auto sighash = MakeDummySighash();
    auto pk_hash = MakeDummyPubkeyHash();
    auto sigs = MakeDummySigs();

    // v2 header = 144 bytes (t_coeffs + c, no batch_hash)
    // v2 footer = 480 bytes
    // Min size = 144 + 480 = 624 bytes

    // Too small
    std::vector<unsigned char> vchSmall(623, 0);
    BOOST_CHECK(!EvalCheckFoldProof(vchSmall, sighash, pk_hash, sigs));

    // Exact minimum — will parse but fail verification (all zeros)
    std::vector<unsigned char> vchMin(624, 0);
    BOOST_CHECK(!EvalCheckFoldProof(vchMin, sighash, pk_hash, sigs));

    // Too large
    std::vector<unsigned char> vchLarge(10001, 0);
    BOOST_CHECK(!EvalCheckFoldProof(vchLarge, sighash, pk_hash, sigs));
}

BOOST_AUTO_TEST_CASE(proof_structure_check_v2)
{
    auto sighash = MakeDummySighash();
    auto pk_hash = MakeDummyPubkeyHash();
    auto sigs = MakeDummySigs();

    // v2 wire format: header(144) + sumcheck(8192) + footer(480) = 8816 bytes
    std::vector<unsigned char> vch(8816, 0);

    // Should parse correctly but fail verification (all zeros)
    BOOST_CHECK(!EvalCheckFoldProof(vch, sighash, pk_hash, sigs));

    // Wrong round count: 7 rounds = 7*64*16 = 7168 bytes
    // Total = 144 + 7168 + 480 = 7792 bytes
    std::vector<unsigned char> vchWrongRounds(7792, 0);
    BOOST_CHECK(!EvalCheckFoldProof(vchWrongRounds, sighash, pk_hash, sigs));
}

BOOST_AUTO_TEST_CASE(consensus_matrix_a_deterministic)
{
    // Matrix A must be identical across multiple derivations
    std::array<std::array<Binius64, MATRIX_A_COLS>, MATRIX_A_ROWS> matA1, matA2;
    LatticeFoldVerifier::DeriveConsensusMatrixA(matA1);
    LatticeFoldVerifier::DeriveConsensusMatrixA(matA2);

    for (size_t i = 0; i < MATRIX_A_ROWS; ++i) {
        for (size_t j = 0; j < MATRIX_A_COLS; ++j) {
            BOOST_CHECK(matA1[i][j] == matA2[i][j]);
            // Elements should be nonzero (random from SHAKE-128)
            BOOST_CHECK(matA1[i][j] != Binius64::zero());
        }
    }
}

BOOST_AUTO_TEST_CASE(batch_hash_recomputation)
{
    // Same sigs must produce same batch_hash
    auto sigs = MakeDummySigs(5);
    std::array<uint8_t, 32> hash1, hash2;
    LatticeFoldVerifier::ComputeBatchHash(sigs, hash1);
    LatticeFoldVerifier::ComputeBatchHash(sigs, hash2);
    BOOST_CHECK(hash1 == hash2);

    // Different sigs must produce different batch_hash
    auto sigs2 = MakeDummySigs(6);
    std::array<uint8_t, 32> hash3;
    LatticeFoldVerifier::ComputeBatchHash(sigs2, hash3);
    BOOST_CHECK(hash1 != hash3);
}

BOOST_AUTO_TEST_CASE(external_binding_different_sighash)
{
    // Two proofs with different sighash must not be interchangeable
    // (Both will fail verification since proofs are zeroed, but the
    // Fiat-Shamir transcript must differ)
    auto pk_hash = MakeDummyPubkeyHash();
    auto sigs = MakeDummySigs();

    uint256 sighash1;
    memset(sighash1.begin(), 0x11, 32);
    uint256 sighash2;
    memset(sighash2.begin(), 0x22, 32);

    // Both should fail (zeroed proof), but they exercise different transcript paths
    std::vector<unsigned char> vch(8816, 0);
    BOOST_CHECK(!EvalCheckFoldProof(vch, sighash1, pk_hash, sigs));
    BOOST_CHECK(!EvalCheckFoldProof(vch, sighash2, pk_hash, sigs));
}

// =========================================================================
// Launch-consensus withdrawal guard (Option A).
//
// OP_CHECKFOLDPROOF is withdrawn from mainnet: the verifier reads the
// statement (t_coeffs, c) from the untrusted blob and every algebraic check
// is homogeneous in the witness, so the all-zero witness satisfies all of
// them; the one non-homogeneous check is a public recomputable Fiat-Shamir
// seed. Mainnet DEPLOYMENT_LATTICEFOLD was ALWAYS_ACTIVE from genesis, and a
// prior branch-landing recipe silently dropped the deactivation once already.
// These assertions are the guard against that happening again.
//
// NOTE: these tests intentionally assert CONFIGURATION, not verifier
// behaviour. The forgery is still reachable wherever the deployment is active
// (the test networks, deliberately, as a playground). What must never regress
// is that mainnet cannot reach it.
// =========================================================================

BOOST_AUTO_TEST_CASE(mainnet_latticefold_deployment_never_active)
{
    const CChainParams& mainParams = Params(CBaseChainParams::MAIN);

    // Mainnet consensus is a height-indexed BST (consensus -> auxpowConsensus),
    // and the tiers are COPIES taken during CMainParams construction. Assert every
    // tier, not just the root: a tier added or re-copied before the deployment
    // block would silently resurrect the opcode above that height.
    const uint32_t heights[] = {0, 1, 2, 100000, 10000000};

    for (uint32_t h : heights) {
        const Consensus::Params& consensus = mainParams.GetConsensus(h);
        const Consensus::BIP9Deployment& lf =
            consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEFOLD];

        // nStartTime=0 / nTimeout=0 => the BIP9 state machine reaches
        // THRESHOLD_FAILED (terminal) for every block, so SCRIPT_VERIFY_LATTICEFOLD
        // is never set on mainnet and EvalCheckFoldProof is unreachable there.
        BOOST_CHECK_MESSAGE(lf.nStartTime != Consensus::BIP9Deployment::ALWAYS_ACTIVE,
            "mainnet DEPLOYMENT_LATTICEFOLD must NOT be ALWAYS_ACTIVE at height " << h
            << " — OP_CHECKFOLDPROOF accepts a zero witness and is withdrawn from "
            "launch consensus");
        BOOST_CHECK_EQUAL(lf.nStartTime, 0);
        BOOST_CHECK_EQUAL(lf.nTimeout, 0);

        // The flag-day (p96/Option D) path must not be wired up either, or it would
        // activate the opcode by height and bypass the BIP9 deactivation entirely.
        BOOST_CHECK_EQUAL(lf.nActivationHeight,
                          Consensus::BIP9Deployment::NO_HEIGHT_ACTIVATION);
        BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(
            h, consensus, Consensus::DEPLOYMENT_LATTICEFOLD));

        // The sibling range-proof deployment (bead x1wf, same zero-generator
        // class) must likewise stay inactive on mainnet.
        const Consensus::BIP9Deployment& bp =
            consensus.vDeployments[Consensus::DEPLOYMENT_LATTICEBP];
        BOOST_CHECK_MESSAGE(bp.nStartTime != Consensus::BIP9Deployment::ALWAYS_ACTIVE,
            "mainnet DEPLOYMENT_LATTICEBP must NOT be ALWAYS_ACTIVE at height " << h);
        BOOST_CHECK_EQUAL(bp.nActivationHeight,
                          Consensus::BIP9Deployment::NOT_SCHEDULED);
        BOOST_CHECK(!Consensus::DeploymentActiveAtHeight(
            h, consensus, Consensus::DEPLOYMENT_LATTICEBP));
    }
}

BOOST_AUTO_TEST_CASE(witness_v3_output_is_relay_nonstandard)
{
    // Containment for the anyone-can-spend posture the deactivation creates.
    // With SCRIPT_VERIFY_LATTICEFOLD unset, a v3 program short-circuits to
    // success (interpreter.cpp:1652) — i.e. anyone-can-spend. That is only safe
    // while v3 outputs cannot be funded through normal relay.
    //
    // v3 = OP_3 (0x53) falls inside the BIP141 s4 future-witness rejection range
    // (OP_2..OP_16) in policy.cpp and is NOT one of the OP_5..OP_9 carve-outs.
    // If someone adds OP_3 to those carve-outs while the deployment is inactive,
    // this test fails — and it must, because that combination is the v6 hazard
    // (see covenant_tests.cpp: htlc_v6_output_is_relay_standard).
    CScript v3out;
    v3out << OP_3 << std::vector<unsigned char>(32, 0xab);
    BOOST_REQUIRE_EQUAL(v3out.size(), 34U);

    txnouttype whichType;
    BOOST_CHECK_MESSAGE(!::IsStandard(v3out, whichType, /*witnessEnabled=*/true),
        "witness v3 must stay relay-nonstandard while DEPLOYMENT_LATTICEFOLD is "
        "inactive, otherwise v3 outputs are fundable AND anyone-can-spend");
}

BOOST_AUTO_TEST_SUITE_END()
