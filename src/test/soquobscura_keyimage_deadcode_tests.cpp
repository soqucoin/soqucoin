// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// soquobscura_keyimage_deadcode_tests.cpp — proof BY EXECUTION that the
// key-image double-spend protection in ConnectBlock cannot run (bead p4wv).
//
// These tests assert that a rule does NOT fire. That is unusual and deliberate.
// Bead r0vn's whole argument is that "scaffolding that never fires is
// indistinguishable from scaffolding that works", and the only way to tell the
// two apart is to execute the case the rule claims to catch and record what
// actually happens. Until now the answer was inferred from reading; here it is
// measured.
//
// WHAT IS DEAD AND WHY
//
// The loop in validation.cpp (SOQ-ARCH-001 Phase 2) resolves each input with
// view.AccessCoins(prevout.hash)->IsAvailable(n). It runs in the LAST pass over
// the block, and UpdateCoins already spent every input during the FIRST pass, so
// IsAvailable is false for all of them and the body is skipped unconditionally.
// Consequence: four reject strings are unreachable
// (bad-txns-conf-no-witness, bad-txns-conf-empty-keyimage,
// bad-txns-conf-duplicate-keyimage, bad-txns-conf-intrablock-duplicate-keyimage),
// vBlockKeyImages is always empty, and WriteKeyImage is never called by the
// connect path, so the DB the cross-block check consults is never populated.
//
// This is the THIRD instance of one root cause. The freeze guard (bead e2n) and
// the USDSOQ input-isolation rule (bead 0r2) were both dead for exactly this
// reason and were both fixed. The asymmetry is visible inside validation.cpp
// itself: DisconnectBlock's mirror loop does the same walk and works, and its
// own comment says why — ApplyTxInUndo has already RESTORED the inputs there.
//
// ⛔ DO NOT "FIX" THIS BY READING BLOCK UNDO. That was the first instinct and it
// is wrong. The ratified design (DL-LATTICEBP-STATE-ANALYSIS-2026-07-18 Part II,
// DL-SOQUOBSCURA-NAMING-POLICY) CUT ring signatures, stealth addresses and
// decoys from launch, and key images exist only to make ring signatures
// double-spend-safe. II.6 records the disposition explicitly: "Key images leave
// launch scope", and Phase 2 says "remove LF+/ring/key-image opcodes from launch
// rules". Reviving the loop would also revive two known defects that have never
// executed: H2, WriteKeyImage has no !fJustCheck guard, so every
// getblocktemplate dry-run would persist key images and the second poll of the
// same template would reject it as a duplicate (BUG-18 verbatim); and C5, no
// witness layout satisfies both script verification and key-image extraction.
//
// The second test below demonstrates the deeper problem concretely: the
// "key image" is just wit.stack.back(), so two honest spends by the same key
// produce the SAME key image. Reviving the rule as written would reject a
// legitimate transaction.

#include "consensus/params.h"
#include "consensus/privacy.h"
#include "test/dilithium_chain_setup.h"
#include "test/testutil.h"   // ScopedRegtestActivation
#include "txdb.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(soquobscura_keyimage_deadcode_tests, DilithiumChainSetup)

// ---------------------------------------------------------------------------
// The measurement, updated for FC4. Two CONFIDENTIAL (witness v10) inputs are
// spent in one transaction with IDENTICAL trailing witness elements, so if the
// key-image loop ran at all the second input would be an intra-block duplicate.
//
// Before FC4 this case proved the loop dead by showing the block CONNECTS
// (the loop resolves inputs after UpdateCoins has spent them; bead p4wv). FC4
// gave v10 its own interpreter dispatch that FAILS CLOSED while the
// confidential verifier is unshipped (bead jzg0, ruling r0vn), so the loop is
// now dead twice over: its inputs resolve too late, AND no v10 spend can
// connect at all while the gates are active. This case pins the stronger
// posture, and still checks the key-image DB directly rather than inferring.
//
// When the activation release ships a real verifier and replaces the
// fail-closed reject, this case must be revisited together with the loop's
// scheduled REMOVAL (p4wv: remove in Phase 2, never revive).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(connectblock_never_extracts_key_images_from_confidential_inputs)
{
    ScopedRegtestActivation on(Consensus::DEPLOYMENT_SOQUOBSCURA, 0);

    const CAmount valA = 3 * COIN, valB = 2 * COIN;
    const CScript v10 = Spk(OP_10);
    COutPoint a = SeedCoin(v10, valA, 0xc1);
    COutPoint b = SeedCoin(v10, valB, 0xc2);

    CMutableTransaction tx; tx.nVersion = 2;
    { CTxIn i0; i0.prevout = a; i0.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(i0); }
    { CTxIn i1; i1.prevout = b; i1.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(i1); }
    // USDSOQ conservation counts v10, so the single output carries the full sum.
    { CTxOut o; o.nValue = valA + valB; o.scriptPubKey = v10; tx.vout.push_back(o); }
    SignInput(tx, 0, v10, valA);
    SignInput(tx, 1, v10, valB);

    // Both witnesses end in the same element, so both "key images" are equal.
    BOOST_REQUIRE(tx.vin[0].scriptWitness.stack.back() == tx.vin[1].scriptWitness.stack.back());
    const LatticeKeyImageHash ki =
        LatticeKeyImageHash::FromSerializedKeyImage(tx.vin[0].scriptWitness.stack.back());

    // BlockIsValid, not RejectReasonFor: the rejection comes from VerifyScript
    // (SCRIPT_ERR_CONFIDENTIAL_USDSOQ_UNVERIFIED), and script failures inside a
    // block carry an EMPTY reject string, which RejectReasonFor cannot tell
    // apart from a valid block. The exact script error is pinned separately in
    // witness_version_allocation_tests / v10_fails_closed_when_both_gates_are_active.
    BOOST_CHECK_MESSAGE(!BlockIsValid({tx}),
        "a v10 spend must FAIL CLOSED while the confidential verifier is unshipped "
        "(FC4 scaffolding, bead jzg0). If this block validates, either a real verifier "
        "landed (update this case alongside the p4wv loop removal) or the fail-closed "
        "dispatch regressed to anyone-can-spend");

    const uint256 tipBefore = chainActive.Tip()->GetBlockHash();
    CBlock rejected = CreateAndProcessBlock({tx}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == tipBefore,
        "a block spending v10 inputs must NOT connect while the verifier is unshipped");

    bool have;
    {
        LOCK(cs_main);
        have = pcoinsdbview->HaveKeyImage(ki.hash);
    }
    BOOST_CHECK_MESSAGE(!have,
        "no key image may be recorded for a confidential spend: the extraction loop is "
        "dead (p4wv) and the spend itself cannot connect (jzg0). Direct evidence, not "
        "inference.");
}

// ---------------------------------------------------------------------------
// The reason a naive revival would be a regression rather than a fix.
//
// The key image is whatever wit.stack.back() happens to be. On every witness
// layout the node actually accepts today that element is NOT bound to the
// outpoint being spent: for a Dilithium-path spend it is the pubkey, identical
// across every output the same key owns. So the moment the loop is made live,
// two honest spends by one owner collide and the second is rejected as a
// double-spend of an output it never touched.
//
// This test pins the collision itself, independent of whether the loop runs, so
// the property is recorded before anyone tries to enable the rule.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(key_image_derivation_is_not_bound_to_the_output_being_spent)
{
    const CScript v10 = Spk(OP_10);
    COutPoint a = SeedCoin(v10, 3 * COIN, 0xc3);
    COutPoint b = SeedCoin(v10, 7 * COIN, 0xc4);   // different outpoint, different value

    CMutableTransaction txA; txA.nVersion = 2;
    { CTxIn i; i.prevout = a; i.nSequence = CTxIn::SEQUENCE_FINAL; txA.vin.push_back(i); }
    { CTxOut o; o.nValue = 3 * COIN; o.scriptPubKey = v10; txA.vout.push_back(o); }
    SignInput(txA, 0, v10, 3 * COIN);

    CMutableTransaction txB; txB.nVersion = 2;
    { CTxIn i; i.prevout = b; i.nSequence = CTxIn::SEQUENCE_FINAL; txB.vin.push_back(i); }
    { CTxOut o; o.nValue = 7 * COIN; o.scriptPubKey = v10; txB.vout.push_back(o); }
    SignInput(txB, 0, v10, 7 * COIN);

    const LatticeKeyImageHash kiA =
        LatticeKeyImageHash::FromSerializedKeyImage(txA.vin[0].scriptWitness.stack.back());
    const LatticeKeyImageHash kiB =
        LatticeKeyImageHash::FromSerializedKeyImage(txB.vin[0].scriptWitness.stack.back());

    BOOST_CHECK_MESSAGE(kiA == kiB,
        "two spends of DIFFERENT confidential outpoints by the same owner derive the SAME "
        "key image, because the key image is defined as the last witness element and that "
        "element is the pubkey. Enabling the ConnectBlock loop without first defining a "
        "real key image would reject the second honest spend as a double-spend. Key images "
        "only mean something under ring signatures, which the ratified design cut from "
        "launch (DL-LATTICEBP-STATE-ANALYSIS Part II, II.6: 'Key images leave launch scope')");
}

BOOST_AUTO_TEST_SUITE_END()
