// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// witness_version_reservation_tests.cpp — SOQ-I009 consensus reservation of
// witness versions whose deployment is not active.
//
// witness_version_allocation_tests.cpp pins the POLICY side: a dormant version
// is relay-nonstandard, and its comment is explicit that this is only
// "containment for the anyone-can-spend posture". Containment at the policy
// layer does not bind a miner. This file pins the CONSENSUS side: a block that
// CREATES such an output is rejected outright, so the anyone-can-spend posture
// is unreachable rather than merely unrelayable.
//
// Why it matters, concretely: with SCRIPT_VERIFY_P2WSH_DILITHIUM unset a v6
// program short-circuits to success in VerifyScript, so a v6 HTLC funded on a
// mainnet that has not activated the deployment confirms and is then spendable
// by anybody. That is loss of funds, not a safe no-op — bead
// premature-witness-standardness-m9mr, and the reason BIP141's
// "anyone-can-spend until activated" default is wrong for a chain that has not
// launched yet.
//
// Regtest has v6 active from height 0, so each case activates or withdraws the
// deployment explicitly rather than relying on the network default.

#include "consensus/params.h"
#include "test/dilithium_chain_setup.h"
#include "test/testutil.h"   // ScopedRegtestActivation

#include <boost/test/unit_test.hpp>

namespace {

//! Withdraw a deployment for the duration of a scope (the inverse of
//! ScopedRegtestActivation, which only turns things ON).
struct ScopedRegtestWithdrawal {
    Consensus::DeploymentPos pos;
    int restore;
    ScopedRegtestWithdrawal(Consensus::DeploymentPos p, int restoreHeight)
        : pos(p), restore(restoreHeight)
    {
        UpdateRegtestActivationHeight(pos, Consensus::BIP9Deployment::NOT_SCHEDULED);
        SelectParams(CBaseChainParams::REGTEST);
    }
    ~ScopedRegtestWithdrawal()
    {
        UpdateRegtestActivationHeight(pos, restore);
        SelectParams(CBaseChainParams::REGTEST);
    }
};

} // namespace

struct WitnessReservationSetup : public DilithiumChainSetup {
    // A minimal correctly-signed spend of `cb` paying everything to `destSpk`.
    // The signature is valid, so any rejection is about the OUTPUT SHAPE alone.
    CMutableTransaction SpendTo(const CTransaction& cb, const CScript& destSpk)
    {
        const CAmount inVal = cb.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;
        CTxIn in;
        in.prevout = COutPoint(cb.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);
        CTxOut out;
        out.nValue = inVal - 10000;
        out.scriptPubKey = destSpk;
        tx.vout.push_back(out);
        SignInput(tx, 0, coinbaseSpk, inVal);
        return tx;
    }
};

BOOST_FIXTURE_TEST_SUITE(witness_version_reservation_tests, WitnessReservationSetup)

// The m9mr hazard, at consensus. With P2WSH-Dilithium withdrawn (mainnet's
// posture), a v6 output is anyone-can-spend — so creating one must be refused.
BOOST_AUTO_TEST_CASE(v6_output_rejected_while_p2wsh_dilithium_dormant)
{
    ScopedRegtestWithdrawal off(Consensus::DEPLOYMENT_P2WSH_DILITHIUM, 0);
    CMutableTransaction tx = SpendTo(coinbaseTxns[0], Spk(OP_6));
    BOOST_CHECK_EQUAL(RejectReasonFor({tx}), "bad-txns-witness-version-not-active");
}

// Reachability control: the identical transaction connects once the deployment
// is active, so the rejection above is about dormancy and nothing else.
BOOST_AUTO_TEST_CASE(v6_output_accepted_once_p2wsh_dilithium_active)
{
    CMutableTransaction tx = SpendTo(coinbaseTxns[1], Spk(OP_6));
    BOOST_CHECK_MESSAGE(RejectReasonFor({tx}).empty(),
        "v6 is ALWAYS_ACTIVE on regtest, so this must connect — otherwise the "
        "dormancy rejection above proves nothing");
}

// v3 (LatticeFold) is retired and never activates on ANY network, so a v3
// output is permanently anyone-can-spend at the script layer. Consensus must
// refuse to create one everywhere, not just on mainnet.
BOOST_AUTO_TEST_CASE(v3_output_rejected_everywhere_latticefold_is_retired)
{
    const int h = chainActive.Height() + 1;
    BOOST_REQUIRE_MESSAGE(
        !Consensus::DeploymentActiveAtHeight(h, Params().GetConsensus(h),
                                             Consensus::DEPLOYMENT_LATTICEFOLD),
        "LatticeFold must be retired on regtest for this test to mean anything");
    CMutableTransaction tx = SpendTo(coinbaseTxns[2], Spk(OP_3));
    BOOST_CHECK_EQUAL(RejectReasonFor({tx}), "bad-txns-witness-version-not-active");
}

// v11-v16 are unallocated (witness_version_allocation_tests
// free_witness_versions_are_v11_through_v16). No deployment can activate them,
// so they must be unconstructable until one is assigned.
BOOST_AUTO_TEST_CASE(unallocated_versions_v11_to_v16_are_unconstructable)
{
    const opcodetype versions[] = {OP_11, OP_12, OP_13, OP_14, OP_15, OP_16};
    for (size_t i = 0; i < 6; i++) {
        CMutableTransaction tx = SpendTo(coinbaseTxns[3 + i], Spk(versions[i]));
        BOOST_CHECK_MESSAGE(
            RejectReasonFor({tx}) == "bad-txns-witness-version-not-active",
            "witness v" << (11 + i) << " must be unconstructable while unallocated");
    }
}

// v5/v7 (USDSOQ) and v8/v9 (BTCSOQ) under mainnet posture. These are the shapes
// whose markers buy consensus exemptions, so their reservation is the part of
// SOQ-I009 that closes the authority-forgery class at the source.
BOOST_AUTO_TEST_CASE(usdsoq_shapes_rejected_while_deployment_withdrawn)
{
    ScopedRegtestWithdrawal off(Consensus::DEPLOYMENT_USDSOQ, 0);
    CMutableTransaction marker = SpendTo(coinbaseTxns[9], Spk(OP_5));
    CMutableTransaction holding = SpendTo(coinbaseTxns[10], Spk(OP_7));

    // The marker carries no asset value, so nothing earlier constrains it and
    // the reservation rule is what refuses it.
    BOOST_CHECK_EQUAL(RejectReasonFor({marker}), "bad-txns-witness-version-not-active");

    // The v7 HOLDING is caught earlier, by the always-on per-asset conservation
    // rule in Consensus::CheckTxInputs (out > in = 0, since no v7 input can
    // exist). Pinned deliberately: the two rules overlap here and the earlier
    // one wins. If this string ever changes to the reservation string, the
    // conservation chokepoint has moved and that is worth knowing.
    BOOST_CHECK_EQUAL(RejectReasonFor({holding}), "bad-txns-usdsoq-not-conserved");
}

BOOST_AUTO_TEST_CASE(btcsoq_shapes_rejected_while_deployment_withdrawn)
{
    ScopedRegtestWithdrawal off(Consensus::DEPLOYMENT_BTCSOQ, 0);
    CMutableTransaction holding = SpendTo(coinbaseTxns[11], Spk(OP_8));
    CMutableTransaction marker  = SpendTo(coinbaseTxns[12], Spk(OP_9));
    // Same overlap as the USDSOQ pair above: conservation pre-empts for the
    // holding, reservation is what catches the marker.
    BOOST_CHECK_EQUAL(RejectReasonFor({holding}), "bad-txns-btcsoq-not-conserved");
    BOOST_CHECK_EQUAL(RejectReasonFor({marker}),  "bad-txns-witness-version-not-active");
}

// The base forms must stay unconditionally constructable — this rule must never
// be able to brick ordinary spending.
BOOST_AUTO_TEST_CASE(v1_base_form_always_constructable)
{
    CMutableTransaction tx = SpendTo(coinbaseTxns[13], Spk(OP_1));
    BOOST_CHECK_MESSAGE(RejectReasonFor({tx}).empty(),
        "v1 Dilithium outputs must never be gated");
}

BOOST_AUTO_TEST_SUITE_END()
