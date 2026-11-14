// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// witness_v11_script_tests.cpp — witness version 11 at the script layer.
//
// An output of witness version 11 is OP_11 and a 32-byte program, the SHA-256
// of one committed witness item: a sub-version byte and a script. A spend's
// witness is [satisfaction items] [committed item] [trailer]. The version runs
// when any of SCRIPT_VERIFY_CTV, SCRIPT_VERIFY_APO and SCRIPT_VERIFY_CSFS is
// set; with the three clear it is dormant and every spend succeeds in a block.
//
// The bytes of the format (the version number 11, the sub-version 0xc0, the
// key type 0x00, the lengths) are written out here and not read from
// script/script.h, so that a constant changed there fails a test here.

#include "amount.h"
#include "crypto/sha256.h"
#include "key.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_bitcoin.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

typedef std::vector<unsigned char> valtype;

//! The three flags of the version's deployments.
const unsigned int V11_FLAGS[] = {SCRIPT_VERIFY_CTV, SCRIPT_VERIFY_APO, SCRIPT_VERIFY_CSFS};

//! The flags a block carries beside the deployment flags a case names.
const unsigned int BLOCK = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                           SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_SCRIPT_RESTORE;

//! The flag relay adds, under which a dormant version and each upgrade hook
//! are refused.
const unsigned int RELAY = SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;

//! The flags of combination `mask` of the three deployments, bit i for V11_FLAGS[i].
unsigned int Deployments(int mask)
{
    unsigned int flags = 0;
    for (int i = 0; i < 3; ++i)
        if (mask & (1 << i))
            flags |= V11_FLAGS[i];
    return flags;
}

valtype Sha256(const valtype& data)
{
    valtype h(32);
    CSHA256().Write(data.data(), data.size()).Finalize(h.data());
    return h;
}

//! The committed item: the sub-version byte and the script.
valtype CommittedItem(const CScript& script, unsigned char subversion = 0xc0)
{
    valtype item(1, subversion);
    item.insert(item.end(), script.begin(), script.end());
    return item;
}

//! OP_11 and the SHA-256 of the committed item.
CScript OutputFor(const valtype& committedItem)
{
    return CScript() << OP_11 << Sha256(committedItem);
}

//! A key item: the type byte and the key.
valtype KeyItem(const CKey& key, unsigned char type = 0x00)
{
    const CPubKey pub = key.GetPubKey();
    valtype item(1, type);
    item.insert(item.end(), pub.begin(), pub.end());
    return item;
}

//! <SHA-256 of the whole key item> OP_CHECKDILITHIUMKEYHASH OP_1
CScript SingleKeyScript(const valtype& keyItem)
{
    return CScript() << Sha256(keyItem) << OP_CHECKDILITHIUMKEYHASH << OP_1;
}

const valtype TRAILER(1, 0x00);

const CAmount AMOUNT = 50 * COIN;

//! A transaction with one input and one output that spends a fixed outpoint.
CMutableTransaction SpendingTx()
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;
    CTxIn in;
    in.prevout = COutPoint(uint256S("0x1111111111111111111111111111111111111111111111111111111111111111"), 0);
    in.nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin.push_back(in);
    tx.vout.push_back(CTxOut(AMOUNT - COIN, CScript() << OP_1 << valtype(32, 0x22)));
    return tx;
}

//! A signature item over the message witness version 6 signs for `script`.
valtype SignV6Message(const CKey& key, const CScript& script, const CTransaction& tx, int hashType)
{
    const uint256 sighash = SignatureHash(script, tx, 0, hashType, AMOUNT, SIGVERSION_WITNESS_V0, nullptr);
    valtype sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    BOOST_REQUIRE_EQUAL(sig.size(), 2420u);
    sig.push_back(static_cast<unsigned char>(hashType));
    return sig;
}

ScriptError Verdict(const CScript& output, const std::vector<valtype>& witness, unsigned int flags,
                    const CTransaction& tx)
{
    CScriptWitness w;
    w.stack = witness;
    ScriptError serr = SCRIPT_ERR_OK;
    TransactionSignatureChecker checker(&tx, 0, AMOUNT);
    const bool ok = VerifyScript(CScript(), output, &w, flags, checker, &serr);
    BOOST_CHECK_MESSAGE(ok == (serr == SCRIPT_ERR_OK),
        "VerifyScript returned " << ok << " with the error " << ScriptErrorString(serr));
    return serr;
}

std::string Name(ScriptError e) { return std::string(ScriptErrorString(e)); }

//! An output locked to one key, and four spends of it by someone who holds no
//! key of it.
struct StrangerAttempts {
    CKey owner, stranger;
    CScript script;
    valtype committed;
    CScript output;
    CTransaction tx;
    std::vector<valtype> nothing, noSatisfaction, strangersKey, ownersKeyV6Message;

    StrangerAttempts() : tx(SpendingTx())
    {
        owner.MakeNewKey(true);
        stranger.MakeNewKey(true);
        const valtype ownerItem = KeyItem(owner);
        const valtype strangerItem = KeyItem(stranger);
        script = SingleKeyScript(ownerItem);
        committed = CommittedItem(script);
        output = OutputFor(committed);

        // One item, the byte every input's last witness item begins with.
        nothing = {TRAILER};
        // The committed item, which the spender reads from the output's
        // funding, and no satisfaction item.
        noSatisfaction = {committed, TRAILER};
        // The stranger's own key and a signature made with it.
        strangersKey = {SignV6Message(stranger, script, tx, SIGHASH_ALL), strangerItem, committed, TRAILER};
        // The owner's key item, which is public once the owner has spent, and
        // a signature the owner made over the message of witness version 6.
        ownersKeyV6Message = {SignV6Message(owner, script, tx, SIGHASH_ALL), ownerItem, committed, TRAILER};
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(witness_v11_script_tests, BasicTestingSetup)

// Where any of the version's three deployments is active, a spend by someone
// who holds no key of the output fails, each for its own reason.
BOOST_AUTO_TEST_CASE(a_v11_output_is_not_spent_by_a_stranger_where_its_deployments_are_active)
{
    const StrangerAttempts a;
    BOOST_REQUIRE_EQUAL(a.output.size(), 34u);

    for (int mask = 1; mask < 8; ++mask) {
        const unsigned int flags = BLOCK | Deployments(mask);
        const ScriptError nothing = Verdict(a.output, a.nothing, flags, a.tx);
        const ScriptError noSatisfaction = Verdict(a.output, a.noSatisfaction, flags, a.tx);
        const ScriptError strangersKey = Verdict(a.output, a.strangersKey, flags, a.tx);
        const ScriptError v6Message = Verdict(a.output, a.ownersKeyV6Message, flags, a.tx);

        BOOST_CHECK_MESSAGE(nothing == SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH,
            "combination " << mask << ": a witness of one item must fail for want of a committed item; got " << Name(nothing));
        BOOST_CHECK_MESSAGE(noSatisfaction == SCRIPT_ERR_INVALID_STACK_OPERATION,
            "combination " << mask << ": the committed item alone must fail at the key-hash check; got " << Name(noSatisfaction));
        BOOST_CHECK_MESSAGE(strangersKey == SCRIPT_ERR_CHECKDILITHIUMKEYHASH,
            "combination " << mask << ": a stranger's key and signature must fail at the key-hash comparison; got " << Name(strangersKey));
        BOOST_CHECK_MESSAGE(v6Message == SCRIPT_ERR_CHECKDILITHIUMKEYHASH,
            "combination " << mask << ": a signature over the message of witness version 6 must not verify; got " << Name(v6Message));
    }
}

// Where the three deployments are inactive the version is dormant: the same
// spends succeed with a block's flags, and with relay's flag each is refused
// with the error of a dormant witness version.
BOOST_AUTO_TEST_CASE(a_v11_output_is_anyone_can_spend_where_its_deployments_are_inactive)
{
    const StrangerAttempts a;
    const std::vector<valtype>* const spends[] = {&a.nothing, &a.noSatisfaction, &a.strangersKey, &a.ownersKeyV6Message};

    for (const std::vector<valtype>* spend : spends) {
        const ScriptError inBlock = Verdict(a.output, *spend, BLOCK, a.tx);
        BOOST_CHECK_MESSAGE(inBlock == SCRIPT_ERR_OK,
            "a dormant version reads nothing and succeeds in a block; got " << Name(inBlock));

        const ScriptError atRelay = Verdict(a.output, *spend, BLOCK | RELAY, a.tx);
        BOOST_CHECK_MESSAGE(atRelay == SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
            "a spend of a dormant version must be refused under relay's flag; got " << Name(atRelay));
    }

    // The flags of witness version 6 and of the asset versions do not start
    // version 11.
    const unsigned int others = SCRIPT_VERIFY_P2WSH_DILITHIUM | SCRIPT_VERIFY_DILITHIUM_KEYHASH |
                                SCRIPT_VERIFY_V6_CONTROLFLOW | SCRIPT_VERIFY_USDSOQ | SCRIPT_VERIFY_BTCSOQ |
                                SCRIPT_VERIFY_SOQUOBSCURA | SCRIPT_VERIFY_PAT | SCRIPT_VERIFY_LATTICEFOLD;
    BOOST_CHECK_EQUAL(Verdict(a.output, a.nothing, BLOCK | others, a.tx), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()
