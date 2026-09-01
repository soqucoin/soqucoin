// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// pat_v2_unfundable_tests.cpp — why witness v2 (PAT) must never be fundable.
//
// Bead pat-v2-anyone-can-spend-ae6u, found by the Phase B chain review 2026-08-31.
//
// THE DEFECT, as driven: DEPLOYMENT_CHECKPATAGG is ALWAYS_ACTIVE on every
// network, so ConnectBlock's versionActive(2) returned true and a v2 output
// could be created. Meanwhile the v2 spend path in interpreter.cpp binds
// nothing an attacker does not control: it delegates to OP_CHECKPATAGG, which
// by design verifies no signature — only the internal consistency of
// attacker-supplied 32-byte tuples — and it references neither the 32-byte
// witness program nor the sighash. A stranger could therefore mint a
// self-consistent proof over values of their choosing and spend ANY v2 output.
// VerifyScript printed ACCEPTED.
//
// ⛔ The unbound spend path is NOT a bug to fix. PAT stores 32-byte
// commitments, not signatures, and VerifyLogarithmicProof structurally
// requires 32-byte fields; a commitment cannot verify a signature. That is
// information-theoretic, and the whitepaper never claimed otherwise
// (§4.3/§5: signatures are verified natively under v0/v1, PAT attests over
// them). So the remedy is not to bind the spend — it is to ensure there is
// never anything to spend.
//
// THE REMEDY, ruled 2026-08-31: PAT's attestation is block metadata — a
// commitment in the coinbase, validated in ConnectBlock — and not an output
// type. Witness v2 is therefore PERMANENTLY unfundable at consensus,
// unconditionally rather than gated on the deployment. OP_CHECKPATAGG stays in
// the binary (audited, harmless) but is no longer load-bearing, which removes
// the coupling that produced this defect.
//
// WHERE EACH HALF IS PINNED:
//   - consensus, the control that protects funds — witness_version_reservation_tests
//     v2_output_unfundable_even_though_checkpatagg_is_active (drives a real block)
//   - relay, the second layer                    — PIN 2 below
//   - the reason both are required               — PIN 1 below

#include "crypto/pat/logarithmic.h"
#include "policy/policy.h"
#include "random.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

typedef std::vector<unsigned char> valtype;

BOOST_FIXTURE_TEST_SUITE(pat_v2_unfundable_tests, BasicTestingSetup)

static valtype RandHashVec()
{
    uint256 h;
    GetRandBytes(h.begin(), 32);
    return valtype(h.begin(), h.end());
}

//! The 34-byte witness form every Soqucoin version uses: OP_N <32 bytes>.
static CScript V2Program(const valtype& program)
{
    CScript spk;
    spk << OP_2 << program;
    return spk;
}

// PIN 1 — the reason v2 must never be fundable.
//
// With SCRIPT_VERIFY_PAT set (as it is on every network, since the deployment
// is ALWAYS_ACTIVE), a stranger spends a victim's v2 output using a proof over
// values they chose freely. The attacker never learns the victim's program
// preimage and never sees a private key.
//
// This test asserts the spend SUCCEEDS. It is a characterisation test, not an
// approval: it records the unbound spend path as a standing fact, so that the
// unfundability rule always has its justification attached. If someone ever
// binds the program and the sighash AND verifies real signatures, this test
// fails loudly and sends the fixer to the bead — at which point re-opening v2
// as a spendable type becomes discussable. Until then, it is the argument.
BOOST_AUTO_TEST_CASE(v2_spend_path_is_unbound_which_is_why_v2_must_be_unfundable)
{
    const valtype victimProgram = RandHashVec();  // attacker never learns the preimage
    const CScript victimScriptPubKey = V2Program(victimProgram);
    BOOST_REQUIRE_EQUAL(victimScriptPubKey.size(), 34U);

    std::vector<valtype> sigs, pks, msgs;
    sigs.push_back(RandHashVec());
    pks.push_back(RandHashVec());
    msgs.push_back(RandHashVec());

    valtype proof_data;
    BOOST_REQUIRE(pat::CreateLogarithmicProof(sigs, pks, msgs, proof_data));
    pat::LogarithmicProof proof;
    BOOST_REQUIRE(pat::ParseLogarithmicProof(proof_data, proof));

    uint32_t n = 1;
    valtype count_blob(4);
    memcpy(count_blob.data(), &n, 4);

    CScriptWitness witness;
    witness.stack.push_back(sigs[0]);
    witness.stack.push_back(pks[0]);
    witness.stack.push_back(msgs[0]);
    witness.stack.push_back(count_blob);
    witness.stack.push_back(proof_data);
    witness.stack.push_back(valtype(proof.pk_agg.begin(), proof.pk_agg.end()));
    witness.stack.push_back(valtype(proof.msg_root.begin(), proof.msg_root.end()));

    BaseSignatureChecker checker;
    ScriptError serror = SCRIPT_ERR_OK;
    const bool spent = VerifyScript(CScript(), victimScriptPubKey, &witness,
                                    SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_PAT,
                                    checker, &serror);

    BOOST_CHECK_MESSAGE(spent,
        "The v2 spend path now REJECTS a self-made proof over attacker-chosen values. "
        "That is a behaviour change: if the proof is genuinely bound to the witness "
        "program and the spending transaction AND real signatures are verified, "
        "re-opening witness v2 as a fundable type becomes discussable. Read bead "
        "pat-v2-anyone-can-spend-ae6u first — the consensus rule in ConnectBlock is "
        "what actually protects funds, and this test is its justification.");
}

// PIN 2 — the relay layer must refuse the shape too.
//
// Consensus unfundability is the control; this is defence in depth. It is
// pinned separately because the two layers reach the same verdict by different
// routes, and the route matters: v2 is non-standard because Solver never names
// the form, which happens BEFORE IsStandard consults the activation mask. That
// is why the v2 bit in validation.cpp's activeWitnessVersions was dead, and why
// removing it changed no behaviour — it only stopped policy from asserting
// something consensus contradicts.
//
// The mask is passed here with EVERY version bit set, so a pass means "refused
// regardless of activation state", not "refused because dormant".
BOOST_AUTO_TEST_CASE(v2_output_is_never_relay_standard)
{
    const CScript spk = V2Program(RandHashVec());
    txnouttype whichType;
    const WitnessVersionMask allVersionsActive = ~WitnessVersionMask(0);

    BOOST_CHECK_MESSAGE(!IsStandard(spk, whichType, /*witnessEnabled=*/true, allVersionsActive),
        "a witness v2 output became relay-standard. Policy must not offer to propagate "
        "a shape that ConnectBlock refuses to create — and if Solver has learned the v2 "
        "form, that is a deliberate relay-policy change that has to be made together "
        "with the consensus rule, not ahead of it (bead pat-v2-anyone-can-spend-ae6u).");
}

BOOST_AUTO_TEST_SUITE_END()
