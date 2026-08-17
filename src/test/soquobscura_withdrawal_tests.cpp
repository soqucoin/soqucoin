// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// SoquObscura — the confidential-output deployment must be DORMANT on every network.
//
// =============================================================================
// WHY THIS FILE EXISTS
//
// The consensus range verifier accepts an all-zero witness carrying a correct
// Fiat-Shamir seed, so a confidential output establishes nothing about the
// amount it commits to. The forgery is proven by execution; the regression
// battery is test/soquobscura_degenerate_witness_tests.cpp. Until a
// corpus-gated verifier replaces it, no network may enforce confidential
// outputs — because "enforcing" them means accepting forged proofs.
//
// This file is the falsifier for that withdrawal. It turns RED the moment
// anyone re-activates the deployment on any network.
//
// ⛔ THE SUBTLETY THAT MAKES THIS TEST NECESSARY, AND NOT MERELY TIDY:
//
// Two independent fields can activate a deployment, and only ONE of them is
// consulted for SoquObscura:
//
//   nStartTime / nTimeout      -> the BIP9 state machine (VersionBitsState)
//   nActivationHeight          -> the height gate (DeploymentActiveAtHeight)
//
// consensus/params.h DeploymentActiveAtHeight() reads ONLY nActivationHeight,
// and when that field is set the BIP9 fields are NOT consulted at all.
// ConnectBlock gates SCRIPT_VERIFY_SOQUOBSCURA on DeploymentActiveAtHeight.
//
// So setting nStartTime=0 / nTimeout=0 — the idiom used to withdraw
// DEPLOYMENT_LATTICEFOLD, which really is BIP9-gated — is a NO-OP here. A
// withdrawal written that way reviews cleanly, reads as correct, and leaves
// the feature active from genesis. That is exactly the defect class this
// project keeps hitting, so the test asserts BOTH mechanisms are closed.
//
// ⚠️ NOT_SCHEDULED (INT_MAX), never NO_HEIGHT_ACTIVATION (-1). The latter is
// the "fall back to BIP9" sentinel, which on the test networks would
// re-activate the feature via ALWAYS_ACTIVE.
// =============================================================================

#include "chainparams.h"
#include "consensus/params.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(soquobscura_withdrawal_tests, BasicTestingSetup)

namespace {

//! The heights probed. ⚠️ GetConsensus() is height-indexed in this codebase
//! (Dogecoin's height-chained consensus params, pConsensusRoot), so the
//! deployment table is NOT necessarily the same object at every height. A check
//! that only looked at height 0 could miss a later consensus revision that
//! re-activates the feature.
const std::vector<uint32_t> kProbeHeights = {
    0, 1, 1000, 44890 /* live stagenet tip at withdrawal */, 1000000, 100000000};

//! Assert the deployment is unreachable by BOTH activation mechanisms.
void CheckSoquObscuraDormant(const std::string& chain)
{
    SelectParams(chain);

    for (uint32_t height : kProbeHeights) {
    const Consensus::Params& c = Params().GetConsensus(height);
    const Consensus::BIP9Deployment& d =
        c.vDeployments[Consensus::DEPLOYMENT_SOQUOBSCURA];

    // --- mechanism 1: the height gate, which is the one that actually governs ---
    BOOST_CHECK_MESSAGE(
        d.nActivationHeight == Consensus::BIP9Deployment::NOT_SCHEDULED,
        chain << ": DEPLOYMENT_SOQUOBSCURA.nActivationHeight is not NOT_SCHEDULED. "
              "This is the field DeploymentActiveAtHeight() reads, so this alone "
              "re-enables confidential outputs and the broken range verifier.");

    // The withdrawal must not be expressed as NO_HEIGHT_ACTIVATION, which falls
    // back to BIP9 and would re-activate via ALWAYS_ACTIVE on the test networks.
    BOOST_CHECK_MESSAGE(
        d.nActivationHeight != Consensus::BIP9Deployment::NO_HEIGHT_ACTIVATION,
        chain << ": nActivationHeight is NO_HEIGHT_ACTIVATION, which defers to the "
              "BIP9 state machine rather than withdrawing the deployment.");

    // --- mechanism 2: BIP9, closed as defence in depth ---
    // If anyone later resets nActivationHeight to NO_HEIGHT_ACTIVATION, BIP9 must
    // not silently activate the feature behind them.
    BOOST_CHECK_MESSAGE(
        d.nStartTime != Consensus::BIP9Deployment::ALWAYS_ACTIVE,
        chain << ": DEPLOYMENT_SOQUOBSCURA.nStartTime is ALWAYS_ACTIVE. Harmless only "
              "while nActivationHeight stays set; a latent re-activation otherwise.");
    BOOST_CHECK_MESSAGE(d.nStartTime == 0,
        chain << ": DEPLOYMENT_SOQUOBSCURA.nStartTime should be 0 (not started).");
    BOOST_CHECK_MESSAGE(d.nTimeout == 0,
        chain << ": DEPLOYMENT_SOQUOBSCURA.nTimeout should be 0 (never activates).");

    // --- the property all of the above exists to guarantee ---
    BOOST_CHECK_MESSAGE(
        !Consensus::DeploymentActiveAtHeight(
            static_cast<int>(height), c, Consensus::DEPLOYMENT_SOQUOBSCURA),
        chain << ": DeploymentActiveAtHeight reports SoquObscura ACTIVE at height "
              << height << ". Confidential outputs would be enforced by a verifier "
              "that accepts forged proofs.");
    }
}

} // namespace

BOOST_AUTO_TEST_CASE(soquobscura_dormant_on_mainnet)
{
    CheckSoquObscuraDormant(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(soquobscura_dormant_on_testnet)
{
    CheckSoquObscuraDormant(CBaseChainParams::TESTNET);
}

BOOST_AUTO_TEST_CASE(soquobscura_dormant_on_regtest)
{
    // ⚠️ Regtest is included DELIBERATELY. Leaving it active would keep every
    // functional test running against a verifier known to accept forged proofs,
    // which is how a broken verifier keeps looking fine.
    CheckSoquObscuraDormant(CBaseChainParams::REGTEST);
}

BOOST_AUTO_TEST_CASE(soquobscura_dormant_on_stagenet)
{
    CheckSoquObscuraDormant(CBaseChainParams::STAGENET);
}

// -----------------------------------------------------------------------------
// Guard: the withdrawal must not have collaterally disabled anything else.
// -----------------------------------------------------------------------------
//
// An earlier revision of the confidential-USDSOQ work allocated witness v6 —
// which is already P2WSH-Dilithium. Had that shipped alongside this withdrawal,
// IsConfidential() would have covered v6 and ConnectBlock's pre-activation
// rejection would have consensus-banned every covenant output. A scan of the
// live stagenet chain found SIX real witness-v6 UTXOs, so that was not a
// hypothetical break. This asserts the deployments that must stay up, stayed up.
BOOST_AUTO_TEST_CASE(withdrawal_does_not_disable_neighbouring_deployments)
{
    for (const std::string& chain :
         {CBaseChainParams::REGTEST, CBaseChainParams::STAGENET}) {
        SelectParams(chain);
        const Consensus::Params& c = Params().GetConsensus(0);

        for (auto pos : {Consensus::DEPLOYMENT_USDSOQ,
                         Consensus::DEPLOYMENT_P2WSH_DILITHIUM}) {
            BOOST_CHECK_MESSAGE(
                Consensus::DeploymentActiveAtHeight(0, c, pos),
                chain << ": a neighbouring deployment went dormant as a side effect "
                      "of the SoquObscura withdrawal. USDSOQ and P2WSH-Dilithium must "
                      "remain active on the test networks.");
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
