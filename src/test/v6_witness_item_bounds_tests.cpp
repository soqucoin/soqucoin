// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// v6_witness_item_bounds_tests.cpp — the bounds on what a witness v6
// (P2WSH-Dilithium) witness carries.
//
// A v6 witness is [satisfaction items...] [witnessScript] [trailer]. Consensus
// holds the satisfaction items, before they are copied onto the execution
// stack, to MAX_V6_SATISFACTION_ITEMS in number and to
// MAX_V6_SATISFACTION_ITEM_SIZE bytes each. The witnessScript keeps its own
// limit, MAX_SCRIPT_SIZE, and the trailer has none. Relay policy
// (IsWitnessStandard) is narrower while the v6 rules are active: at most
// MAX_STANDARD_V6_SATISFACTION_ITEMS satisfaction items, a witnessScript of at
// most MAX_STANDARD_V6_SCRIPT_SIZE bytes, and every other item either at most
// MAX_STANDARD_V6_ITEM_SIZE bytes or of the length of an ML-DSA-44 signature
// or public key.
//
// Three suites. The first drives the consensus bound through VerifyScript on
// both sides of each figure and compares the policy figures with the consensus
// ones. The second drives the policy rule through IsWitnessStandard with the
// v6 bit of the activation mask set and clear. The third funds v6 outputs in a
// mined regtest block and spends them through the mempool and in a block, with
// the v6 deployment active and with it not scheduled. Every figure is read
// from its constant, and the two consensus figures are also pinned to their
// values.

#include "chainparams.h"
#include "coins.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/dilithium_chain_setup.h"
#include "test/test_bitcoin.h"
#include "txmempool.h"
#include "validation.h"

extern "C" {
#include "crypto/dilithium/api.h"
}

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

typedef std::vector<unsigned char> valtype;

const unsigned int P2WSH = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2WSH_DILITHIUM;

//! The v6 branch with OP_DROP and OP_EQUALVERIFY live; the scripts below use both.
const unsigned int ACTIVE = P2WSH | SCRIPT_VERIFY_V6_CONTROLFLOW;

//! Every handler live: the three swap flags, the restored set and the
//! flag-gated covenant opcodes.
const unsigned int FULL = ACTIVE | SCRIPT_VERIFY_DILITHIUM_KEYHASH | SCRIPT_VERIFY_SCRIPT_RESTORE |
                          SCRIPT_VERIFY_CTV | SCRIPT_VERIFY_CSFS | SCRIPT_VERIFY_APO;

const WitnessVersionMask V6_ACTIVE = WitnessVersionBit(6);
const WitnessVersionMask V6_DORMANT = 0;

CScript V6ProgramFor(const CScript& witnessScript)
{
    uint256 h;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(h.begin());
    return CScript() << OP_6 << valtype(h.begin(), h.end());
}

//! A witnessScript that drops n satisfaction items and leaves one true item.
CScript DropsOf(size_t n)
{
    CScript s;
    for (size_t i = 0; i < n; ++i)
        s << OP_DROP;
    s << OP_1;
    return s;
}

//! A witnessScript of exactly `size` bytes that drops one satisfaction item
//! and leaves one true item. The padding is OP_0 OP_DROP pairs, with one
//! OP_0 OP_0 OP_EQUALVERIFY where the parity needs it.
CScript ScriptOfSize(size_t size)
{
    BOOST_REQUIRE(size >= 5);
    CScript s;
    s << OP_DROP;
    size_t padding = size - 2;
    if (padding % 2 == 1) {
        s << OP_0 << OP_0 << OP_EQUALVERIFY;
        padding -= 3;
    }
    for (size_t i = 0; i < padding / 2; ++i)
        s << OP_0 << OP_DROP;
    s << OP_1;
    BOOST_REQUIRE_EQUAL(s.size(), size);
    return s;
}

//! The trailer the templates carry: the length of a 0x00-prefixed public key.
valtype Trailer() { return valtype(STANDARD_V6_PUBKEY_SIZE + 1, 0x00); }

//! [items...] [witnessScript] [trailer]
CScriptWitness WitnessOf(const std::vector<valtype>& items, const valtype& witnessScript, const valtype& trailer)
{
    CScriptWitness w;
    w.stack = items;
    w.stack.push_back(witnessScript);
    w.stack.push_back(trailer);
    return w;
}

CScriptWitness WitnessOf(const std::vector<valtype>& items, const CScript& ws)
{
    return WitnessOf(items, valtype(ws.begin(), ws.end()), Trailer());
}

//! The verdict of VerifyScript on the v6 program of `ws` spent with `witness`.
ScriptError VerdictForWitness(const CScript& ws, const CScriptWitness* witness, unsigned int flags)
{
    ScriptError serr = SCRIPT_ERR_UNKNOWN_ERROR;
    const bool ok = VerifyScript(CScript(), V6ProgramFor(ws), witness, flags, BaseSignatureChecker(), &serr);
    BOOST_CHECK_EQUAL(ok, serr == SCRIPT_ERR_OK);
    return serr;
}

//! The same with the witness [items...] [ws] [trailer].
ScriptError VerdictFor(const CScript& ws, const std::vector<valtype>& items, unsigned int flags = ACTIVE)
{
    const CScriptWitness w = WitnessOf(items, ws);
    return VerdictForWitness(ws, &w, flags);
}

std::string Verdict(ScriptError e) { return std::string(ScriptErrorString(e)); }

} // namespace

BOOST_FIXTURE_TEST_SUITE(v6_witness_item_bounds_tests, BasicTestingSetup)

// A satisfaction item of MAX_V6_SATISFACTION_ITEM_SIZE bytes passes and one
// byte more does not. An empty item passes.
BOOST_AUTO_TEST_CASE(a_satisfaction_item_is_held_to_the_item_size)
{
    const CScript ws = DropsOf(1);
    BOOST_CHECK_EQUAL(VerdictFor(ws, {valtype(MAX_V6_SATISFACTION_ITEM_SIZE, 0x01)}), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(ws, {valtype(MAX_V6_SATISFACTION_ITEM_SIZE + 1, 0x01)}), SCRIPT_ERR_PUSH_SIZE);
    BOOST_CHECK_EQUAL(VerdictFor(ws, {valtype()}), SCRIPT_ERR_OK);
}

// The bound covers the first satisfaction item and the last one, the item
// just before the witnessScript.
BOOST_AUTO_TEST_CASE(the_first_and_the_last_satisfaction_item_are_held)
{
    const CScript ws = DropsOf(3);
    const valtype small(1, 0x01);
    const valtype atBound(MAX_V6_SATISFACTION_ITEM_SIZE, 0x01);
    const valtype above(MAX_V6_SATISFACTION_ITEM_SIZE + 1, 0x01);

    BOOST_CHECK_EQUAL(VerdictFor(ws, {small, small, small}), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(ws, {atBound, atBound, atBound}), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(ws, {above, small, small}), SCRIPT_ERR_PUSH_SIZE);
    BOOST_CHECK_EQUAL(VerdictFor(ws, {small, above, small}), SCRIPT_ERR_PUSH_SIZE);
    BOOST_CHECK_EQUAL(VerdictFor(ws, {small, small, above}), SCRIPT_ERR_PUSH_SIZE);
}

// The witnessScript and the trailer are not satisfaction items. A witnessScript
// longer than MAX_V6_SATISFACTION_ITEM_SIZE stays valid up to its own limit,
// MAX_SCRIPT_SIZE, and a trailer longer than MAX_V6_SATISFACTION_ITEM_SIZE
// stays valid.
BOOST_AUTO_TEST_CASE(the_witnessScript_and_the_trailer_are_outside_the_bound)
{
    const std::vector<valtype> item(1, valtype(1, 0x01));

    BOOST_CHECK_EQUAL(VerdictFor(ScriptOfSize(MAX_V6_SATISFACTION_ITEM_SIZE + 1), item), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(ScriptOfSize(MAX_SCRIPT_SIZE), item), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(ScriptOfSize(MAX_SCRIPT_SIZE + 1), item), SCRIPT_ERR_SCRIPT_SIZE);

    const CScript ws = DropsOf(1);
    const CScriptWitness longTrailer = WitnessOf(item, valtype(ws.begin(), ws.end()),
                                                 valtype(MAX_V6_SATISFACTION_ITEM_SIZE + 1, 0x00));
    BOOST_CHECK_EQUAL(VerdictForWitness(ws, &longTrailer, ACTIVE), SCRIPT_ERR_OK);
}

// MAX_V6_SATISFACTION_ITEMS satisfaction items pass and one more does not,
// whatever the items hold.
BOOST_AUTO_TEST_CASE(the_satisfaction_items_are_held_to_their_number)
{
    const size_t atBound = MAX_V6_SATISFACTION_ITEMS;
    // DropsOf spends one script byte on each item.
    BOOST_REQUIRE(atBound + 2 <= (size_t)MAX_SCRIPT_SIZE);
    const std::vector<valtype> full(atBound, valtype(1, 0x01));
    const std::vector<valtype> oneMore(atBound + 1, valtype(1, 0x01));
    const std::vector<valtype> oneMoreEmpty(atBound + 1, valtype());

    BOOST_CHECK_EQUAL(VerdictFor(DropsOf(atBound), full), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(DropsOf(atBound + 1), oneMore), SCRIPT_ERR_STACK_SIZE);
    BOOST_CHECK_EQUAL(VerdictFor(DropsOf(atBound + 1), oneMoreEmpty), SCRIPT_ERR_STACK_SIZE);
}

// A witness with no satisfaction item is within the bound. A witness of fewer
// than two items has no witnessScript and is refused as it was.
BOOST_AUTO_TEST_CASE(a_witness_with_no_satisfaction_item_and_the_short_witnesses)
{
    const CScript ws = CScript() << OP_1;
    BOOST_CHECK_EQUAL(VerdictFor(ws, std::vector<valtype>()), SCRIPT_ERR_OK);

    CScriptWitness one;
    one.stack.push_back(valtype(ws.begin(), ws.end()));
    BOOST_CHECK_EQUAL(VerdictForWitness(ws, &one, ACTIVE), SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    const CScriptWitness none;
    BOOST_CHECK_EQUAL(VerdictForWitness(ws, &none, ACTIVE), SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    BOOST_CHECK_EQUAL(VerdictForWitness(ws, nullptr, ACTIVE), SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
}

// The bound is in force in every flag state in which the v6 branch runs. The
// witnesses here need no flag-gated opcode: an empty witnessScript leaves its
// one item as the result, and OP_CAT, which has no flag, joins a true item and
// the empty items above it into one. With v6 dormant a witness outside the
// bound is valid, as every v6 spend is.
BOOST_AUTO_TEST_CASE(the_bound_follows_the_v6_flag)
{
    const CScript leaveOne;
    const std::vector<valtype> atSize(1, valtype(MAX_V6_SATISFACTION_ITEM_SIZE, 0x01));
    const std::vector<valtype> oversized(1, valtype(MAX_V6_SATISFACTION_ITEM_SIZE + 1, 0x01));

    auto joinOf = [](size_t n) {
        CScript s;
        for (size_t i = 0; i + 1 < n; ++i)
            s << OP_CAT;
        return s;
    };
    auto itemsOf = [](size_t n) {
        std::vector<valtype> items(n);
        items[0] = valtype(1, 0x01);
        return items;
    };
    const size_t atNumber = MAX_V6_SATISFACTION_ITEMS;

    const unsigned int running[] = {
        SCRIPT_VERIFY_P2WSH_DILITHIUM,
        P2WSH,
        ACTIVE,
        FULL,
        FULL | STANDARD_SCRIPT_VERIFY_FLAGS,
    };
    for (unsigned int flags : running) {
        const ScriptError sizeAt = VerdictFor(leaveOne, atSize, flags);
        const ScriptError sizeAbove = VerdictFor(leaveOne, oversized, flags);
        const ScriptError numberAt = VerdictFor(joinOf(atNumber), itemsOf(atNumber), flags);
        const ScriptError numberAbove = VerdictFor(joinOf(atNumber + 1), itemsOf(atNumber + 1), flags);
        BOOST_CHECK_MESSAGE(sizeAt == SCRIPT_ERR_OK,
            "flags=" << flags << ": a satisfaction item at the size got " << Verdict(sizeAt));
        BOOST_CHECK_MESSAGE(sizeAbove == SCRIPT_ERR_PUSH_SIZE,
            "flags=" << flags << ": an oversized satisfaction item got " << Verdict(sizeAbove));
        BOOST_CHECK_MESSAGE(numberAt == SCRIPT_ERR_OK,
            "flags=" << flags << ": the full number of satisfaction items got " << Verdict(numberAt));
        BOOST_CHECK_MESSAGE(numberAbove == SCRIPT_ERR_STACK_SIZE,
            "flags=" << flags << ": one satisfaction item too many got " << Verdict(numberAbove));
    }

    const unsigned int dormant[] = {
        SCRIPT_VERIFY_NONE,
        SCRIPT_VERIFY_WITNESS,
        (FULL | STANDARD_SCRIPT_VERIFY_FLAGS) & ~SCRIPT_VERIFY_P2WSH_DILITHIUM,
    };
    for (unsigned int flags : dormant) {
        BOOST_CHECK_MESSAGE(VerdictFor(leaveOne, oversized, flags) == SCRIPT_ERR_OK,
            "flags=" << flags << ": v6 is dormant and the oversized item must not be read");
        BOOST_CHECK_MESSAGE(VerdictFor(joinOf(atNumber + 1), itemsOf(atNumber + 1), flags) == SCRIPT_ERR_OK,
            "flags=" << flags << ": v6 is dormant and the items must not be counted");
    }
}

// The policy rule admits no witness the consensus bound refuses: every length
// it admits for an item is at most the consensus item size, the standard
// witnessScript size is at most the consensus script size, and the standard
// number of satisfaction items is below the consensus number. The two exempt
// lengths are those of an ML-DSA-44 signature and public key, and the consensus
// item size is a signature with its hashtype byte. The two consensus figures
// are pinned to their values.
BOOST_AUTO_TEST_CASE(the_policy_figures_are_within_the_consensus_figures)
{
    BOOST_CHECK(MAX_STANDARD_V6_ITEM_SIZE <= MAX_V6_SATISFACTION_ITEM_SIZE);
    BOOST_CHECK(STANDARD_V6_SIGNATURE_SIZE + 1 <= MAX_V6_SATISFACTION_ITEM_SIZE);
    BOOST_CHECK(STANDARD_V6_PUBKEY_SIZE + 1 <= MAX_V6_SATISFACTION_ITEM_SIZE);
    BOOST_CHECK(MAX_STANDARD_V6_SCRIPT_SIZE <= (unsigned int)MAX_SCRIPT_SIZE);
    BOOST_CHECK(MAX_STANDARD_V6_SATISFACTION_ITEMS < MAX_V6_SATISFACTION_ITEMS);

    BOOST_CHECK_EQUAL(STANDARD_V6_SIGNATURE_SIZE, (unsigned int)pqcrystals_dilithium2_BYTES);
    BOOST_CHECK_EQUAL(STANDARD_V6_PUBKEY_SIZE, (unsigned int)pqcrystals_dilithium2_PUBLICKEYBYTES);
    BOOST_CHECK_EQUAL(STANDARD_V6_PUBKEY_SIZE, (unsigned int)CPubKey::SIZE);
    BOOST_CHECK_EQUAL(MAX_V6_SATISFACTION_ITEM_SIZE, (unsigned int)pqcrystals_dilithium2_BYTES + 1);

    // The two consensus figures by value. A change to either is a consensus
    // change: on a network where witness v6 is active, a lower figure refuses
    // a witness this release accepts and a higher figure accepts one it
    // refuses.
    BOOST_CHECK_EQUAL(MAX_V6_SATISFACTION_ITEM_SIZE, 2421u);
    BOOST_CHECK_EQUAL(MAX_V6_SATISFACTION_ITEMS, 1000u);
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// The policy rule, through IsWitnessStandard.
// ---------------------------------------------------------------------------
namespace {

//! A coins view holding one transaction with a witness v6, v0, v1, v5 and v7
//! output, each a 32-byte program, and a v6 version byte over a 20-byte
//! program, and the verdict of IsWitnessStandard on a spend of them.
//! IsWitnessStandard reads the spent output's script and the witness and
//! verifies neither, so the programs and the witnessScript bytes are
//! placeholders.
struct StandardnessSetup : public BasicTestingSetup {
    enum { V6 = 0, V0 = 1, V1 = 2, V5 = 3, V7 = 4, V6_SHORT_PROGRAM = 5 };

    CCoinsView base;
    CCoinsViewCache view;
    CMutableTransaction funding;

    StandardnessSetup() : view(&base)
    {
        funding.vout.push_back(CTxOut(COIN, CScript() << OP_6 << valtype(32, 0x06)));
        funding.vout.push_back(CTxOut(COIN, CScript() << OP_0 << valtype(32, 0x07)));
        funding.vout.push_back(CTxOut(COIN, CScript() << OP_1 << valtype(32, 0x08)));
        funding.vout.push_back(CTxOut(COIN, CScript() << OP_5 << valtype(32, 0x09)));
        funding.vout.push_back(CTxOut(COIN, CScript() << OP_7 << valtype(32, 0x0a)));
        funding.vout.push_back(CTxOut(COIN, CScript() << OP_6 << valtype(20, 0x0b)));
        view.ModifyCoins(funding.GetHash())->FromTx(funding, 0);
    }

    //! A spend of the funded outputs `outs`, input i carrying witnesses[i].
    CTransaction SpendOf(const std::vector<unsigned int>& outs, const std::vector<CScriptWitness>& witnesses) const
    {
        BOOST_REQUIRE_EQUAL(outs.size(), witnesses.size());
        CMutableTransaction spend;
        for (size_t i = 0; i < outs.size(); ++i) {
            spend.vin.push_back(CTxIn(COutPoint(funding.GetHash(), outs[i])));
            spend.vin[i].scriptWitness = witnesses[i];
        }
        spend.vout.push_back(CTxOut(COIN, CScript() << OP_1 << valtype(32, 0x08)));
        return CTransaction(spend);
    }

    bool Standard(unsigned int out, const CScriptWitness& w, WitnessVersionMask mask) const
    {
        return IsWitnessStandard(SpendOf({out}, {w}), view, mask);
    }
};

//! A witnessScript of `size` bytes for the policy rule, which does not parse it.
valtype ScriptBytes(size_t size) { return valtype(size, (unsigned char)OP_1); }

//! [items...] [witnessScript] [trailer]. The witnessScript is longer than
//! MAX_STANDARD_V6_ITEM_SIZE, a length the rule refuses for any other item.
CScriptWitness PolicyWitness(const std::vector<valtype>& items)
{
    return WitnessOf(items, ScriptBytes(MAX_STANDARD_V6_ITEM_SIZE + 20), Trailer());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(v6_witness_item_bounds_policy_tests, StandardnessSetup)

// MAX_STANDARD_V6_SATISFACTION_ITEMS satisfaction items are standard and one
// more is not. With the v6 rules dormant no v6 limit applies.
BOOST_AUTO_TEST_CASE(the_number_of_satisfaction_items)
{
    const valtype small(1, 0x01);
    const CScriptWitness atBound = PolicyWitness(std::vector<valtype>(MAX_STANDARD_V6_SATISFACTION_ITEMS, small));
    const CScriptWitness above = PolicyWitness(std::vector<valtype>(MAX_STANDARD_V6_SATISFACTION_ITEMS + 1, small));

    BOOST_CHECK(Standard(V6, atBound, V6_ACTIVE));
    BOOST_CHECK(!Standard(V6, above, V6_ACTIVE));
    BOOST_CHECK(Standard(V6, atBound, V6_DORMANT));
    BOOST_CHECK(Standard(V6, above, V6_DORMANT));
}

// An item other than the witnessScript is standard at MAX_STANDARD_V6_ITEM_SIZE
// bytes or less and at the length of a signature or a public key, each bare or
// one byte longer. The rule is the same for the first satisfaction item, the
// last one and the trailer.
BOOST_AUTO_TEST_CASE(the_length_of_an_item_other_than_the_witnessScript)
{
    const struct {
        size_t size;
        bool standard;
    } lengths[] = {
        {0, true},
        {MAX_STANDARD_V6_ITEM_SIZE, true},
        {MAX_STANDARD_V6_ITEM_SIZE + 1, false},
        {STANDARD_V6_PUBKEY_SIZE - 1, false},
        {STANDARD_V6_PUBKEY_SIZE, true},
        {STANDARD_V6_PUBKEY_SIZE + 1, true},
        {STANDARD_V6_PUBKEY_SIZE + 2, false},
        {STANDARD_V6_SIGNATURE_SIZE - 1, false},
        {STANDARD_V6_SIGNATURE_SIZE, true},
        {STANDARD_V6_SIGNATURE_SIZE + 1, true},
        {STANDARD_V6_SIGNATURE_SIZE + 2, false},
    };
    const valtype small(1, 0x01);
    const valtype script = ScriptBytes(MAX_STANDARD_V6_ITEM_SIZE + 20);

    for (const auto& length : lengths) {
        const valtype item(length.size, 0x00);
        const struct {
            const char* position;
            CScriptWitness witness;
        } cases[] = {
            {"the first satisfaction item", WitnessOf({item, small, small}, script, Trailer())},
            {"the last satisfaction item", WitnessOf({small, small, item}, script, Trailer())},
            {"the trailer", WitnessOf({small, small, small}, script, item)},
        };
        for (const auto& c : cases) {
            BOOST_CHECK_MESSAGE(Standard(V6, c.witness, V6_ACTIVE) == length.standard,
                c.position << " of " << length.size << " bytes must be "
                << (length.standard ? "standard" : "non-standard") << " while v6 is active");
            BOOST_CHECK_MESSAGE(Standard(V6, c.witness, V6_DORMANT),
                c.position << " of " << length.size << " bytes must be standard while v6 is dormant");
        }
    }
}

// A witnessScript of MAX_STANDARD_V6_SCRIPT_SIZE bytes is standard and one byte
// more is not. The item lengths do not apply to it.
BOOST_AUTO_TEST_CASE(the_size_of_the_witnessScript)
{
    const std::vector<valtype> items(1, valtype(1, 0x01));
    const CScriptWitness atBound = WitnessOf(items, ScriptBytes(MAX_STANDARD_V6_SCRIPT_SIZE), Trailer());
    const CScriptWitness above = WitnessOf(items, ScriptBytes(MAX_STANDARD_V6_SCRIPT_SIZE + 1), Trailer());

    BOOST_CHECK(Standard(V6, atBound, V6_ACTIVE));
    BOOST_CHECK(!Standard(V6, above, V6_ACTIVE));
    BOOST_CHECK(Standard(V6, above, V6_DORMANT));
    BOOST_CHECK(Standard(V6, WitnessOf(items, ScriptBytes(MAX_STANDARD_V6_ITEM_SIZE + 1), Trailer()), V6_ACTIVE));
}

// An input with no witness is skipped. A v6 witness of one item has neither a
// witnessScript nor a trailer and is non-standard while v6 is active. The
// witnessScript and the trailer alone are standard.
BOOST_AUTO_TEST_CASE(the_short_witnesses)
{
    BOOST_CHECK(Standard(V6, CScriptWitness(), V6_ACTIVE));
    BOOST_CHECK(Standard(V6, CScriptWitness(), V6_DORMANT));

    CScriptWitness one;
    one.stack.push_back(ScriptBytes(1));
    BOOST_CHECK(!Standard(V6, one, V6_ACTIVE));
    BOOST_CHECK(Standard(V6, one, V6_DORMANT));

    BOOST_CHECK(Standard(V6, PolicyWitness(std::vector<valtype>()), V6_ACTIVE));
}

// The witness shapes of the hashlock claim, the hashlock refund and the
// key-hash 2-of-2 are standard.
BOOST_AUTO_TEST_CASE(the_template_witnesses_are_standard)
{
    const valtype keyHash(32, 0x02), hashLock(32, 0x03);
    CScript htlc;
    htlc << OP_IF
           << OP_SHA256 << hashLock << OP_EQUALVERIFY << keyHash << OP_CHECKDILITHIUMKEYHASH << OP_1
         << OP_ELSE
           << CScriptNum(500) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << keyHash << OP_CHECKDILITHIUMKEYHASH << OP_1
         << OP_ENDIF;
    CScript twoOfTwo;
    twoOfTwo << keyHash << OP_CHECKDILITHIUMKEYHASH << keyHash << OP_CHECKDILITHIUMKEYHASH << OP_1;
    const valtype htlcBytes(htlc.begin(), htlc.end());
    const valtype twoOfTwoBytes(twoOfTwo.begin(), twoOfTwo.end());

    const valtype sig(STANDARD_V6_SIGNATURE_SIZE + 1, 0x01);  // with its hashtype byte
    const valtype key(STANDARD_V6_PUBKEY_SIZE, 0x04);
    const valtype preimage(32, 0x05);
    const valtype claimBranch(1, 0x01);
    const valtype refundBranch;

    BOOST_CHECK(Standard(V6, WitnessOf({sig, key, preimage, claimBranch}, htlcBytes, Trailer()), V6_ACTIVE));
    BOOST_CHECK(Standard(V6, WitnessOf({sig, key, refundBranch}, htlcBytes, Trailer()), V6_ACTIVE));
    BOOST_CHECK(Standard(V6, WitnessOf({sig, key, sig, key}, twoOfTwoBytes, Trailer()), V6_ACTIVE));
}

// The rule reads bit 6 of the mask and nothing else, a mask of 0 applies no v6
// limit, every input is read, and the rule applies to a 32-byte witness v6
// program alone: not to witness v1, not to the versions on either side of v6,
// and not to a v6 version byte over a program of another length.
BOOST_AUTO_TEST_CASE(the_rule_reads_the_v6_bit_and_the_v6_inputs)
{
    const CScriptWitness above =
        PolicyWitness(std::vector<valtype>(MAX_STANDARD_V6_SATISFACTION_ITEMS + 1, valtype(1, 0x01)));

    WitnessVersionMask allButV6 = 0;
    for (int v = 0; v <= 16; ++v) {
        if (v != 6)
            allButV6 |= WitnessVersionBit(v);
    }
    BOOST_CHECK(Standard(V6, above, allButV6));
    BOOST_CHECK(!Standard(V6, above, allButV6 | V6_ACTIVE));
    BOOST_CHECK(IsWitnessStandard(SpendOf({V6}, {above}), view, V6_DORMANT));

    // A witness v1 input whose witness, read as a v6 witness, is outside the
    // standard number of satisfaction items by one and outside the item
    // lengths: every item is MAX_STANDARD_V6_ITEM_SIZE + 1 bytes, which the
    // v6 rule admits for the witnessScript alone. The item in the
    // witnessScript's place is inside MAX_STANDARD_V6_SCRIPT_SIZE.
    CScriptWitness outside;
    outside.stack.assign(MAX_STANDARD_V6_SATISFACTION_ITEMS + 3, valtype(MAX_STANDARD_V6_ITEM_SIZE + 1, 0x01));
    BOOST_CHECK(Standard(V1, outside, V6_ACTIVE));
    BOOST_CHECK(Standard(V1, outside, V6_DORMANT));

    // The same witness on the other programs, with every bit of the mask set.
    const WitnessVersionMask everyBit = allButV6 | V6_ACTIVE;
    BOOST_CHECK(!Standard(V6, outside, everyBit));
    BOOST_CHECK(Standard(V5, outside, everyBit));
    BOOST_CHECK(Standard(V7, outside, everyBit));
    BOOST_CHECK(Standard(V6_SHORT_PROGRAM, outside, everyBit));

    // The v6 input second, after an input the rule passes.
    BOOST_CHECK(!IsWitnessStandard(SpendOf({V1, V6}, {outside, above}), view, V6_ACTIVE));
    BOOST_CHECK(IsWitnessStandard(SpendOf({V1, V6}, {outside, above}), view, V6_DORMANT));
}

// The witness v0 rule, [items...] [witnessScript], is the same in both states:
// its three limits on both sides.
BOOST_AUTO_TEST_CASE(the_witness_v0_rule_is_the_same_in_both_states)
{
    const WitnessVersionMask masks[] = {V6_DORMANT, V6_ACTIVE};
    for (WitnessVersionMask mask : masks) {
        auto v0 = [&](size_t nItems, size_t itemSize, size_t scriptSize) {
            CScriptWitness w;
            w.stack.assign(nItems, valtype(itemSize, 0x01));
            w.stack.push_back(ScriptBytes(scriptSize));
            return Standard(V0, w, mask);
        };
        const size_t items = MAX_STANDARD_P2WSH_STACK_ITEMS;
        const size_t itemSize = MAX_STANDARD_P2WSH_STACK_ITEM_SIZE;
        const size_t scriptSize = MAX_STANDARD_P2WSH_SCRIPT_SIZE;
        BOOST_CHECK(v0(items, itemSize, scriptSize));
        BOOST_CHECK(!v0(items + 1, itemSize, scriptSize));
        BOOST_CHECK(!v0(items, itemSize + 1, scriptSize));
        BOOST_CHECK(!v0(items, itemSize, scriptSize + 1));
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// The chain path: v6 outputs funded in a mined regtest block, where the v6
// deployments are active from height 0, and spent through the mempool and in
// a block on the same tip.
// ---------------------------------------------------------------------------
namespace {

const CAmount FEE = COIN;

//! Sets fRequireStandard for the life of the object and puts back what it found.
struct ScopedRequireStandard {
    const bool previous;
    explicit ScopedRequireStandard(bool value) : previous(fRequireStandard) { fRequireStandard = value; }
    ~ScopedRequireStandard() { fRequireStandard = previous; }
};

//! Moves the regtest activation height of the v6 deployment, on every consensus
//! tier, for the life of the object, and puts back the height it found.
struct ScopedV6ActivationHeight {
    const int previous;
    explicit ScopedV6ActivationHeight(int nHeight)
        : previous(Params().GetConsensus(0).vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nActivationHeight)
    {
        UpdateRegtestActivationHeight(Consensus::DEPLOYMENT_P2WSH_DILITHIUM, nHeight);
        SelectParams(CBaseChainParams::REGTEST);
    }
    ~ScopedV6ActivationHeight()
    {
        UpdateRegtestActivationHeight(Consensus::DEPLOYMENT_P2WSH_DILITHIUM, previous);
        SelectParams(CBaseChainParams::REGTEST);
    }
};

struct ItemBoundsChainSetup : public DilithiumChainSetup {
    CMutableTransaction F;
    std::vector<CScript> scripts;
    CAmount each;

    ItemBoundsChainSetup() : each(0) {}

    //! F: coinbase[0] to one v6 output for each witnessScript, mined.
    void Fund(const std::vector<CScript>& witnessScripts)
    {
        scripts = witnessScripts;
        const CAmount cbValue = coinbaseTxns[0].vout[0].nValue;
        each = (cbValue - FEE) / (CAmount)scripts.size();
        BOOST_REQUIRE(each > 2 * FEE);
        F.nVersion = 2;
        F.vin.push_back(CTxIn(COutPoint(coinbaseTxns[0].GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        for (const CScript& ws : scripts)
            F.vout.push_back(CTxOut(each, V6ProgramFor(ws)));
        SignInput(F, 0, coinbaseSpk, cbValue);
        const CBlock bF = CreateAndProcessBlock(std::vector<CMutableTransaction>(1, F), coinbaseSpk);
        BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == bF.GetHash(), "the funding block must connect");
    }

    //! S: spends F:n to the coinbase key. Witness: the items, the output's
    //! witnessScript and a 0x00-prefixed trailer.
    CMutableTransaction Spend(unsigned int n, const std::vector<valtype>& items) const
    {
        CMutableTransaction S;
        S.nVersion = 2;
        S.vin.push_back(CTxIn(COutPoint(F.GetHash(), n), CScript(), CTxIn::SEQUENCE_FINAL));
        S.vout.push_back(CTxOut(each - FEE, coinbaseSpk));
        S.vin[0].scriptWitness = WitnessOf(items, scripts[n]);
        return S;
    }

    //! The relay verdict: the reject reason, or "" when accepted. The mempool is
    //! emptied after each try, so every spend is judged on its own.
    std::string Relay(const CMutableTransaction& S)
    {
        LOCK(cs_main);
        CValidationState st;
        const bool ok = AcceptToMemoryPool(mempool, st, MakeTransactionRef(S), false, nullptr, nullptr, true, 0);
        const std::string reason = ok ? std::string() : FormatStateMessage(st);
        BOOST_TEST_MESSAGE("relay: " << (ok ? std::string("accepted") : reason));
        mempool.clear();
        return reason;
    }

    bool ValidInABlock(const CMutableTransaction& S) { return BlockIsValid(std::vector<CMutableTransaction>(1, S)); }
};

std::string OrAccepted(const std::string& reason) { return reason.empty() ? std::string("accepted") : reason; }

//! The reject reason of the witness standardness check, as AcceptToMemoryPool
//! words it, and the full reasons of the mempool's script check for an item
//! above the consensus size and for a witness above the consensus number, as
//! FormatStateMessage prints them: the mandatory wording, the text of the
//! script error and the reject code.
const std::string NONSTANDARD = "bad-witness-nonstandard";
const std::string ITEM_SIZE_REFUSAL = "mandatory-script-verify-flag-failed (Push value size limit exceeded) (code 16)";
const std::string ITEM_NUMBER_REFUSAL = "mandatory-script-verify-flag-failed (Stack size limit exceeded) (code 16)";

} // namespace

BOOST_FIXTURE_TEST_SUITE(v6_witness_item_bounds_chain_tests, ItemBoundsChainSetup)

// The consensus bound. A satisfaction item above MAX_V6_SATISFACTION_ITEM_SIZE
// and a witness of more than MAX_V6_SATISFACTION_ITEMS satisfaction items are
// refused in a block and at relay, with standardness required and without it.
// At each figure the spend connects in a block and passes the mempool's script
// check.
BOOST_AUTO_TEST_CASE(a_witness_outside_the_consensus_bound_is_refused_at_relay_and_in_a_block)
{
    BOOST_REQUIRE_MESSAGE(fRequireStandard,
        "unit tests must run with fRequireStandard set, as mainnet and stagenet do");
    const size_t number = MAX_V6_SATISFACTION_ITEMS;
    Fund({DropsOf(1), DropsOf(number), DropsOf(number + 1)});

    const valtype small(1, 0x01);
    const CMutableTransaction itemAtBound = Spend(0, {valtype(MAX_V6_SATISFACTION_ITEM_SIZE, 0x01)});
    const CMutableTransaction itemAbove = Spend(0, {valtype(MAX_V6_SATISFACTION_ITEM_SIZE + 1, 0x01)});
    const CMutableTransaction numberAtBound = Spend(1, std::vector<valtype>(number, small));
    const CMutableTransaction numberAbove = Spend(2, std::vector<valtype>(number + 1, small));

    // In a block. An empty block on the same tip connects: the refusals are
    // the spends'.
    BOOST_CHECK(BlockIsValid(std::vector<CMutableTransaction>()));
    BOOST_CHECK_MESSAGE(ValidInABlock(itemAtBound), "a block holding an item at the size must connect");
    BOOST_CHECK_MESSAGE(!ValidInABlock(itemAbove), "a block holding an item above the size must fail ConnectBlock");
    BOOST_CHECK_MESSAGE(ValidInABlock(numberAtBound), "a block holding the full number of items must connect");
    BOOST_CHECK_MESSAGE(!ValidInABlock(numberAbove), "a block holding one item too many must fail ConnectBlock");

    // At relay with standardness required. An item at the consensus size has
    // the length of a signature with its hashtype byte, which is standard.
    std::string r = Relay(itemAtBound);
    BOOST_CHECK_MESSAGE(r.empty(), "an item at the size must be accepted at relay; got: " << r);
    r = Relay(itemAbove);
    BOOST_CHECK_MESSAGE(r.find(NONSTANDARD) != std::string::npos,
        "an item above the size must be refused at relay as non-standard; got: " << OrAccepted(r));
    r = Relay(numberAtBound);
    BOOST_CHECK_MESSAGE(r.find(NONSTANDARD) != std::string::npos,
        "the full consensus number of items is above the standard number and must be refused at relay; got: "
        << OrAccepted(r));
    r = Relay(numberAbove);
    BOOST_CHECK_MESSAGE(r.find(NONSTANDARD) != std::string::npos,
        "one item too many must be refused at relay as non-standard; got: " << OrAccepted(r));

    // At relay without it, as regtest and testnet run by default: the
    // mempool's script check holds the consensus bound alone. Each refusal is
    // the script check's mandatory one, matched in full with the text of its
    // script error, and the spend beside it differs by one byte or one item;
    // the first suite pins the two error codes.
    {
        ScopedRequireStandard notRequired(false);
        r = Relay(itemAtBound);
        BOOST_CHECK_MESSAGE(r.empty(), "an item at the size must pass the mempool's script check; got: " << r);
        r = Relay(itemAbove);
        BOOST_CHECK_EQUAL(r, ITEM_SIZE_REFUSAL);
        r = Relay(numberAtBound);
        BOOST_CHECK_MESSAGE(r.empty(), "the full number of items must pass the mempool's script check; got: " << r);
        r = Relay(numberAbove);
        BOOST_CHECK_EQUAL(r, ITEM_NUMBER_REFUSAL);
    }
}

// The policy rule. A witness of one satisfaction item more than
// MAX_STANDARD_V6_SATISFACTION_ITEMS is refused at relay and connects in a
// block; at the figure the spend is accepted at relay and connects.
BOOST_AUTO_TEST_CASE(a_witness_above_the_standard_number_of_items_is_refused_at_relay_and_valid_in_a_block)
{
    BOOST_REQUIRE_MESSAGE(fRequireStandard,
        "unit tests must run with fRequireStandard set, as mainnet and stagenet do");
    const size_t number = MAX_STANDARD_V6_SATISFACTION_ITEMS;
    Fund({DropsOf(number), DropsOf(number + 1)});

    const valtype small(1, 0x01);
    const CMutableTransaction atBound = Spend(0, std::vector<valtype>(number, small));
    const CMutableTransaction above = Spend(1, std::vector<valtype>(number + 1, small));

    // The controls on the same tip: an empty block and the spend at the figure.
    BOOST_CHECK(BlockIsValid(std::vector<CMutableTransaction>()));
    BOOST_CHECK_MESSAGE(ValidInABlock(atBound), "a block holding the standard number of items must connect");
    std::string r = Relay(atBound);
    BOOST_CHECK_MESSAGE(r.empty(), "the standard number of items must be accepted at relay; got: " << r);

    // One item more: relay refuses it and a block may carry it.
    r = Relay(above);
    BOOST_CHECK_MESSAGE(r.find(NONSTANDARD) != std::string::npos,
        "one item above the standard number must be refused at relay as non-standard; got: " << OrAccepted(r));
    BOOST_CHECK_MESSAGE(ValidInABlock(above), "a block holding one item above the standard number must connect");

    // Without the standardness requirement the same spend is accepted: the
    // refusal is the policy rule's.
    {
        ScopedRequireStandard notRequired(false);
        r = Relay(above);
        BOOST_CHECK_MESSAGE(r.empty(),
            "one item above the standard number must be accepted where standardness is not required; got: " << r);
    }
}

// Both rules follow the v6 deployment. With it not scheduled, as on mainnet,
// the mempool applies no v6 limit and a block holds no v6 bound: the two
// spends that relay refuses while v6 is active are accepted and connect.
BOOST_AUTO_TEST_CASE(no_v6_limit_applies_while_the_v6_deployment_is_not_active)
{
    BOOST_REQUIRE_MESSAGE(fRequireStandard,
        "unit tests must run with fRequireStandard set, as mainnet and stagenet do");
    const size_t number = MAX_STANDARD_V6_SATISFACTION_ITEMS;
    Fund({DropsOf(1), DropsOf(number + 1)});

    const CMutableTransaction itemAbove = Spend(0, {valtype(MAX_V6_SATISFACTION_ITEM_SIZE + 1, 0x01)});
    const CMutableTransaction numberAbove = Spend(1, std::vector<valtype>(number + 1, valtype(1, 0x01)));

    // Active, as the chain was mined.
    std::string r = Relay(itemAbove);
    BOOST_CHECK_MESSAGE(r.find(NONSTANDARD) != std::string::npos,
        "an item above the consensus size must be refused at relay while v6 is active; got: " << OrAccepted(r));
    r = Relay(numberAbove);
    BOOST_CHECK_MESSAGE(r.find(NONSTANDARD) != std::string::npos,
        "one item above the standard number must be refused at relay while v6 is active; got: " << OrAccepted(r));

    {
        ScopedV6ActivationHeight notScheduled(Consensus::BIP9Deployment::NOT_SCHEDULED);
        r = Relay(itemAbove);
        BOOST_CHECK_MESSAGE(r.empty(),
            "an item above the consensus size must be accepted at relay while v6 is dormant; got: " << r);
        r = Relay(numberAbove);
        BOOST_CHECK_MESSAGE(r.empty(),
            "one item above the standard number must be accepted at relay while v6 is dormant; got: " << r);
        BOOST_CHECK_MESSAGE(ValidInABlock(itemAbove),
            "a block holding an item above the consensus size must connect while v6 is dormant");
        BOOST_CHECK_MESSAGE(ValidInABlock(numberAbove),
            "a block holding one item above the standard number must connect while v6 is dormant");
    }
}

BOOST_AUTO_TEST_SUITE_END()
