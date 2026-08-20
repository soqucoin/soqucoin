// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// sigop_budget_tests.cpp — what each witness version actually charges against
// the block DoS budget, and which limit binds first. Bead v7xm, fork-risk class
// F6 (sigop accounting).
//
// F6's premise on the bead is that unknown witness versions charge 0 sigops:
// correct while dormant, a DoS surface the moment an expensive verifier
// activates. Measuring it changes the picture in two ways worth writing down.
//
// FIRST: the charge table is stale, not merely conservative. The counter's own
// comment says "Witness v7+: unknown future program. Soft-fork safe: charge 0",
// but v7 (USDSOQ holding), v8 (BTCSOQ holding) and v9 (BTCSOQ authority marker)
// are ALLOCATED. v7 and v8 spend through the same audited single-key Dilithium
// path as v1, so each one performs a real ML-DSA-44 verification and is charged
// nothing, while v1 doing the identical work is charged 1. That is the same
// staleness that left policy.cpp claiming v10-v16 were unallocated after v10 was
// assigned to Tier A.
//
// SECOND, and it is why this is a tidy-up rather than an emergency: BLOCK WEIGHT
// BINDS LONG BEFORE SIGOPS DO. A Dilithium-shaped input costs about 3,901 weight
// units (2,421-byte signature plus a 1,313-byte prefixed pubkey), so a full
// block holds roughly 1,025 of them. That is 1.3% of the 80,000 sigop budget and
// about 179 ms of verification. The sigop budget is not the control that is
// holding anything back, and charging v7/v8 correctly would not change what an
// attacker can do today. The arithmetic is asserted below so that stops being an
// assumption: if the signature size, the weight limit or the sigop budget ever
// move far enough for sigops to become the binding constraint, this fails.
//
// The exposure that F6 is really about therefore lives entirely in the DORMANT
// verifiers, and in the fact that the post-quantum verification-cost system
// meant to price them does not exist in code. See verify_cost_tests.cpp.

#include "consensus/consensus.h"
#include "script/interpreter.h"
#include "script/script.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(sigop_budget_tests, BasicTestingSetup)

namespace {

CScript Program(int version, size_t programLen = 32)
{
    CScript s;
    s << (version == 0 ? OP_0 : CScript::EncodeOP_N(version));
    s << std::vector<unsigned char>(programLen, 0x01);
    return s;
}

//! A Dilithium-shaped witness: [signature+hashtype, 0x00||pubkey].
CScriptWitness DilithiumWitness()
{
    CScriptWitness w;
    w.stack.push_back(std::vector<unsigned char>(2421, 0x01));  // ML-DSA-44 sig + sighash byte
    w.stack.push_back(std::vector<unsigned char>(1313, 0x00));  // 0x00 || 1312-byte pubkey
    return w;
}

size_t Charge(int version, unsigned int flags, const CScriptWitness& w)
{
    return CountWitnessSigOps(CScript(), Program(version), &w, flags);
}

} // namespace

// ---------------------------------------------------------------------------
// THE TABLE. Transcribed from CountWitnessSigOps and asserted, so the charge for
// a version cannot change without a test changing with it. A version that starts
// costing real verification work while charging nothing is the F6 hazard, and
// this is where that becomes visible.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(witness_sigop_charges_are_pinned)
{
    const CScriptWitness w = DilithiumWitness();
    const unsigned int flags = SCRIPT_VERIFY_WITNESS;

    struct Row { int version; size_t charge; const char* note; };
    const Row table[] = {
        { 0, 0, "v0 <32> takes the P2WSH branch, which counts CHECKSIG-family opcodes in "
                "whatever the LAST witness item parses as. Here that is a pubkey, which "
                "contains none, so the charge is 0. Note the charge for this shape is "
                "therefore witness-dependent and attacker-chosen; that is standard P2WSH "
                "behaviour and is safe only because the program hash commits to the script. "
                "Moot in practice: v0 <32> is unspendable anyway (bead trp6)" },
        { 1, 1, "Dilithium single key: one ML-DSA verify, charged 1" },
        { 2, 1, "PAT aggregate: one aggregate verify per input" },
        { 3, 1, "LatticeFold+, retired but still counted" },
        { 4, 1, "Lattice-BP++ / SoquObscura range proof" },
        { 5, 1, "USDSOQ authority marker" },
        { 6, 0, "P2WSH-Dilithium, charged 0 while its flag is clear (no script runs)" },
        { 7, 0, "⚠️ USDSOQ holding: spends via the v1 Dilithium path, so it performs a "
                "REAL ML-DSA verify and is charged NOTHING. v1 doing the same work costs 1" },
        { 8, 0, "⚠️ BTCSOQ holding: identical situation to v7" },
        { 9, 0, "BTCSOQ authority marker: default-deny at the script layer, but authority "
                "txs skip per-input verification and are checked M-of-N in ConnectBlock" },
        { 10, 0, "unallocated at the script layer (Tier A confidential USDSOQ elsewhere)" },
        { 16, 0, "unallocated" },
    };

    for (const Row& r : table) {
        BOOST_CHECK_MESSAGE(Charge(r.version, flags, w) == r.charge,
            "witness v" + std::to_string(r.version) + " charges " +
            std::to_string(Charge(r.version, flags, w)) + " sigops, table says " +
            std::to_string(r.charge) + ". " + r.note);
    }
}

// v0 with a 20-byte program is the P2WPKH shape and charges 1, which is the
// carve-out the counter documents. Worth pinning separately because the script
// layer cannot actually spend that shape at all (bead trp6): it is charged for
// work it will never do.
BOOST_AUTO_TEST_CASE(v0_keyhash_charges_one_for_work_it_can_never_perform)
{
    const CScriptWitness w = DilithiumWitness();
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(), Program(0, 20), &w, SCRIPT_VERIFY_WITNESS), 1u);
}

// Nothing is charged when witness verification is off, which is correct: no
// script runs, so no verification is performed.
BOOST_AUTO_TEST_CASE(no_charge_without_witness_verification)
{
    const CScriptWitness w = DilithiumWitness();
    for (int v = 0; v <= 16; ++v) {
        BOOST_CHECK_MESSAGE(Charge(v, /*flags=*/0, w) == 0,
            "witness v" + std::to_string(v) + " charged sigops with SCRIPT_VERIFY_WITNESS clear");
    }
}

// ---------------------------------------------------------------------------
// WHICH LIMIT ACTUALLY BINDS. This is the assertion that turns "v7/v8 charge
// nothing" from an alarming sentence into a sized one. If block weight stops
// being the binding constraint for Dilithium-shaped inputs, the sigop
// undercharge becomes exploitable and this test is what says so.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(block_weight_binds_before_the_sigop_budget)
{
    // An input spending a Dilithium-path output: 36-byte outpoint, 4-byte
    // sequence, 1-byte empty scriptSig length (all base bytes, x4), plus the
    // witness stack (x1).
    const int64_t baseBytes    = 36 + 4 + 1;
    const int64_t witnessBytes = 2421 + 1313 + 3;   // + compact-size prefixes
    const int64_t weightPerInput = baseBytes * WITNESS_SCALE_FACTOR + witnessBytes;

    const int64_t maxInputs = MAX_BLOCK_WEIGHT / weightPerInput;

    BOOST_TEST_MESSAGE("Dilithium input weight " << weightPerInput
                       << " WU, max inputs per block " << maxInputs
                       << ", sigop budget " << MAX_BLOCK_SIGOPS_COST);

    // Even if EVERY such input were charged the full 1 sigop, a weight-full block
    // uses a small fraction of the budget. So the sigop limit is not the control
    // preventing a verification-heavy block, and correcting the v7/v8 undercharge
    // would not change an attacker's options.
    BOOST_CHECK_MESSAGE(maxInputs * 1 < MAX_BLOCK_SIGOPS_COST / 10,
        "a weight-full block of Dilithium-path inputs would now consume more than a tenth "
        "of the sigop budget (" + std::to_string(maxInputs) + " of " +
        std::to_string(MAX_BLOCK_SIGOPS_COST) + "). The sigop budget is becoming the binding "
        "constraint, so the v7/v8/v9 zero-charge is no longer harmless and must be fixed");

    // And the corollary: weight is what caps verification work, so it is the
    // number to reason about when an expensive verifier is considered for
    // activation. Recorded here rather than in a comment because it is the whole
    // basis for treating F6 as sizing rather than as an emergency.
    BOOST_CHECK_MESSAGE(maxInputs < 2000,
        "more than 2000 verification-bearing inputs now fit in a block; re-derive the "
        "validation-time budget before activating any additional verifier");
}

BOOST_AUTO_TEST_SUITE_END()
