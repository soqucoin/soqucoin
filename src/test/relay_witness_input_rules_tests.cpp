// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// relay_witness_input_rules_tests.cpp — two relay rules on an input that
// spends a witness program, on a mined regtest chain with standardness
// required, as mainnet and stagenet require it.
//
//   The scriptSig. A transaction is refused at relay when an input that
//   spends a witness program carries a scriptSig that is not empty, with the
//   reason "witness-scriptsig-not-empty". The rule reads the output each
//   input spends and the scriptSig of the input. No signature of a witness
//   spend covers its scriptSig and the transaction id does, so a copy with
//   bytes added there is the same payment under another id. There are two
//   exceptions, both of a running version 11 output whose script this
//   release evaluates: the version's own rule refuses a scriptSig on its
//   spend, and a template of OP_CHECKTEMPLATEVERIFY covers the scriptSig
//   of every input of the transaction. Neither copy is valid in a block.
//   A committed item of an undefined sub-version
//   and a script with a reserved opcode succeed before that rule is read.
//
//   The hash opcodes. While witness version 6 or 11 runs, an input of the
//   version is non-standard when its script holds more than 16 hash opcodes.
//   The rule reads the witnessScript of version 6 and the script of the
//   committed item of version 11. The count is over the whole script as
//   CScript::GetOp decodes it: a byte inside a push is left out, and an
//   opcode in a branch that does not run is counted. The interpreter's walk
//   of a version 11 script ends at the first reserved byte; the count goes
//   on past it.
//
// Neither is a rule on blocks. A block that holds what relay refuses here
// connects, and one case for each rule holds that. The exceptions are a spend
// of a running version 11 output with a scriptSig, where the script is one
// this release evaluates, and bytes added to the scriptSig of any input of a
// transaction that such a script holds to a template: relay refuses each by
// the first rule and a block does not connect with either. The third case
// holds the first.
//
// Two suites. The first sends transactions through the mempool and in blocks
// the case builds. The second calls the two policy functions with a coins
// view of its own.

#include "amount.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "test/dilithium_chain_setup.h"
#include "test/test_bitcoin.h"
#include "txmempool.h"
#include "utilstrencodings.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

typedef std::vector<unsigned char> valtype;

const CAmount FEE = COIN;
const std::string ACCEPTED = "accepted";
const std::string SCRIPTSIG = "witness-scriptsig-not-empty";
const std::string WITNESS_NONSTANDARD = "bad-witness-nonstandard";
//! The number of hash opcodes a standard script of version 6 or 11 may hold.
const unsigned int LIMIT = MAX_STANDARD_SCRIPT_HASH_OPCODES;
//! The one satisfaction item of every script spend of this file.
const valtype ITEM(32, 0x42);

valtype Sha256(const valtype& data)
{
    valtype h(CSHA256::OUTPUT_SIZE);
    CSHA256().Write(data.data(), data.size()).Finalize(h.data());
    return h;
}

//! `count` OP_SHA256 over the satisfaction item, then a comparison with what
//! they leave. It evaluates to true for ITEM.
CScript HashChain(unsigned int count)
{
    CScript script;
    valtype h = ITEM;
    for (unsigned int i = 0; i < count; ++i) {
        script << OP_SHA256;
        h = Sha256(h);
    }
    script << h << OP_EQUAL;
    return script;
}

//! The committed item of version 11: the sub-version byte and the script.
valtype CommittedItem(const CScript& script, unsigned char subversion = WITNESS_V11_SUBVERSION_SCRIPT)
{
    valtype item(1, subversion);
    item.insert(item.end(), script.begin(), script.end());
    return item;
}

//! The output of a script: OP_6 and the SHA-256 of the witnessScript, or
//! OP_11 and the SHA-256 of the committed item.
CScript OutputFor(int version, const CScript& script)
{
    if (version == 6)
        return CScript() << OP_6 << Sha256(valtype(script.begin(), script.end()));
    return CScript() << OP_11 << Sha256(CommittedItem(script));
}

//! The two scriptSigs the cases add to a finished transaction: the push of
//! the one byte 00, and a push of 40 bytes.
std::vector<CScript> AddedScriptSigs()
{
    return {CScript() << valtype(1, 0x00), CScript() << valtype(40, 0x5a)};
}

//! Sets fRequireStandard for the life of the object and puts back what it found.
struct ScopedRequireStandard {
    const bool previous;
    explicit ScopedRequireStandard(bool value) : previous(fRequireStandard) { fRequireStandard = value; }
    ~ScopedRequireStandard() { fRequireStandard = previous; }
};

struct WitnessInputSetup : public DilithiumChainSetup {
    WitnessInputSetup()
    {
        // Eight more blocks, so that the first eight coinbases are mature.
        for (int i = 0; i < 8; ++i)
            BOOST_REQUIRE(Connects({}));
    }

    ~WitnessInputSetup() { mempool.clear(); }

    //! The mempool's answer to a transaction, ACCEPTED or the reject reason,
    //! and the validation state the answer left.
    std::string Verdict(const CMutableTransaction& tx, CValidationState& state)
    {
        LOCK(cs_main);
        bool fMissingInputs = false;
        if (AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), false, &fMissingInputs, nullptr, true, 0))
            return ACCEPTED;
        if (fMissingInputs)
            return "missing-inputs";
        return state.GetRejectReason();
    }

    std::string Verdict(const CMutableTransaction& tx)
    {
        CValidationState state;
        return Verdict(tx, state);
    }

    //! A block on the tip with the given transactions and no other, handed to
    //! the node. True when it is the new tip. The mempool is emptied first:
    //! the block's coinbase is the template's, which claims the fees of what
    //! the mempool held.
    bool Connects(const std::vector<CMutableTransaction>& txns)
    {
        mempool.clear();
        const CBlock block = CreateAndProcessBlock(txns, coinbaseSpk);
        LOCK(cs_main);
        return chainActive.Tip()->GetBlockHash() == block.GetHash();
    }

    bool Unspent(const COutPoint& out)
    {
        LOCK(cs_main);
        const CCoins* coins = pcoinsTip->AccessCoins(out.hash);
        return coins && coins->IsAvailable(out.n);
    }

    //! Coinbase n of the fixture paid into one output, signed.
    CMutableTransaction Fund(size_t n, const CScript& spk)
    {
        const CTransaction& cb = coinbaseTxns[n];
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(COutPoint(cb.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vout.push_back(CTxOut(cb.vout[0].nValue - FEE, spk));
        SignInput(tx, 0, coinbaseSpk, cb.vout[0].nValue);
        return tx;
    }

    //! A confirmed output of version 6 or 11 for the script.
    CMutableTransaction Confirmed(size_t n, int version, const CScript& script)
    {
        const CMutableTransaction funding = Fund(n, OutputFor(version, script));
        BOOST_REQUIRE_MESSAGE(Connects({funding}), "the block that funds a version " << version << " output did not connect");
        return funding;
    }

    //! A spend of output 0 of `funding`, an output of version 6 or 11 for the
    //! script, with ITEM as its one satisfaction item.
    CMutableTransaction SpendScript(const CMutableTransaction& funding, int version, const CScript& script)
    {
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(COutPoint(funding.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vout.push_back(CTxOut(funding.vout[0].nValue - FEE, coinbaseSpk));
        std::vector<valtype>& stack = tx.vin[0].scriptWitness.stack;
        stack.push_back(ITEM);
        if (version == 6) {
            stack.push_back(valtype(script.begin(), script.end()));
            stack.push_back(PrefixedPubkey(coinbasePkBytes));
        } else {
            stack.push_back(CommittedItem(script));
            stack.push_back(valtype(1, 0x00));
        }
        return tx;
    }
};

//! A coins view with one output of each witness version 0 to 16 (output n is
//! version n), then a 20-byte program of version 6 and an output that is no
//! witness program. The two policy functions read the spent output's script,
//! the scriptSig and the witness and verify nothing, so the programs are
//! placeholders.
struct PolicySetup : public BasicTestingSetup {
    enum { SHORT_PROGRAM = 17, NO_PROGRAM = 18 };

    CCoinsView base;
    CCoinsViewCache view;
    CMutableTransaction funding;

    PolicySetup() : view(&base)
    {
        for (int version = 0; version <= 16; ++version)
            funding.vout.push_back(CTxOut(COIN, CScript() << (version == 0 ? OP_0 : (opcodetype)(OP_1 + version - 1)) << valtype(32, (unsigned char)version)));
        funding.vout.push_back(CTxOut(COIN, CScript() << OP_6 << valtype(20, 0x06)));
        funding.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
        view.ModifyCoins(funding.GetHash())->FromTx(funding, 0);
    }

    CMutableTransaction SpendOf(const std::vector<unsigned int>& outs) const
    {
        CMutableTransaction spend;
        for (unsigned int out : outs)
            spend.vin.push_back(CTxIn(COutPoint(funding.GetHash(), out)));
        spend.vout.push_back(CTxOut(COIN, CScript() << OP_1 << valtype(32, 0x01)));
        return spend;
    }

    //! IsWitnessStandard for a spend of output `out` whose witness holds one
    //! satisfaction item, then `scriptItem`, then a trailer of the byte 00.
    bool Standard(unsigned int out, const valtype& scriptItem, WitnessVersionMask mask) const
    {
        CMutableTransaction spend = SpendOf({out});
        spend.vin[0].scriptWitness.stack = {ITEM, scriptItem, valtype(1, 0x00)};
        return IsWitnessStandard(CTransaction(spend), view, mask);
    }
};

//! The script item of a version for the bytes of a script: the bytes for
//! version 6, and the bytes after the script sub-version byte for version 11.
valtype ScriptItem(int version, const valtype& scriptBytes)
{
    if (version == 6)
        return scriptBytes;
    valtype item(1, WITNESS_V11_SUBVERSION_SCRIPT);
    item.insert(item.end(), scriptBytes.begin(), scriptBytes.end());
    return item;
}

const WitnessVersionMask RUNNING = WitnessVersionBit(6) | WitnessVersionBit(WITNESS_V11_VERSION);

} // namespace

BOOST_FIXTURE_TEST_SUITE(relay_witness_input_rules_tests, WitnessInputSetup)

// A signed spend of a version 1 output, and two copies of it with bytes added
// to the scriptSig after signing, by a party that holds no key. Each copy has
// its own transaction id. Relay refuses each copy with the rule's reason, the
// reject code of a non-standard transaction and no score, and the state is
// not marked as possible corruption, since the transaction id covers what the
// rule reads. The transaction as it was signed is then accepted.
BOOST_AUTO_TEST_CASE(a_scriptsig_added_to_a_signed_spend_of_a_version_1_output_is_refused_at_relay)
{
    BOOST_REQUIRE_MESSAGE(fRequireStandard, "the unit fixture applies standardness, as mainnet and stagenet do");
    const CMutableTransaction original = Fund(0, coinbaseSpk);
    for (const CScript& added : AddedScriptSigs()) {
        CMutableTransaction changed = original;
        changed.vin[0].scriptSig = added;
        BOOST_REQUIRE(changed.GetHash() != original.GetHash());

        CValidationState state;
        const std::string verdict = Verdict(changed, state);
        BOOST_CHECK_MESSAGE(verdict == SCRIPTSIG, "scriptSig " << HexStr(added) << ": \"" << verdict << "\"");
        int nDoS = -1;
        BOOST_CHECK(state.IsInvalid(nDoS));
        BOOST_CHECK_MESSAGE(nDoS == 0, "score " << nDoS);
        BOOST_CHECK_MESSAGE(state.GetRejectCode() == REJECT_NONSTANDARD, "code " << state.GetRejectCode());
        BOOST_CHECK(!state.CorruptionPossible());
        BOOST_CHECK_EQUAL(mempool.size(), 0u);
        mempool.clear();
    }
    BOOST_CHECK_EQUAL(Verdict(original), ACCEPTED);
}

// The same for a spend of a version 6 output while the version runs. The
// output's script is one hash and a comparison, so the spend carries no
// signature at all.
BOOST_AUTO_TEST_CASE(a_scriptsig_added_to_a_spend_of_a_running_version_6_output_is_refused_at_relay)
{
    const CScript script = HashChain(1);
    const CMutableTransaction funding = Confirmed(0, 6, script);
    const CMutableTransaction original = SpendScript(funding, 6, script);
    for (const CScript& added : AddedScriptSigs()) {
        CMutableTransaction changed = original;
        changed.vin[0].scriptSig = added;
        const std::string verdict = Verdict(changed);
        BOOST_CHECK_MESSAGE(verdict == SCRIPTSIG, "scriptSig " << HexStr(added) << ": \"" << verdict << "\"");
        mempool.clear();
    }
    BOOST_CHECK_EQUAL(Verdict(original), ACCEPTED);
}

// A spend of a running version 11 output with a scriptSig. For a script this
// release evaluates, as here, the rules of version 11 hold the scriptSig of
// its input empty in a block too. Relay
// refuses the transaction with the rule's reason, and a block that holds it
// does not connect.
BOOST_AUTO_TEST_CASE(a_scriptsig_on_a_spend_of_a_running_version_11_output_is_refused_at_relay_and_in_a_block)
{
    const CScript script = HashChain(1);
    const CMutableTransaction funding = Confirmed(0, 11, script);
    const CMutableTransaction original = SpendScript(funding, 11, script);
    CMutableTransaction changed = original;
    changed.vin[0].scriptSig = AddedScriptSigs()[0];

    BOOST_CHECK_EQUAL(Verdict(changed), SCRIPTSIG);
    BOOST_CHECK_EQUAL(mempool.size(), 0u);
    BOOST_CHECK(!Connects({changed}));
    BOOST_CHECK(Unspent(COutPoint(funding.GetHash(), 0)));
    BOOST_CHECK_EQUAL(Verdict(original), ACCEPTED);
}

// The rule holds for a transaction when any one of its inputs carries the
// scriptSig. Here the second of two signed inputs does.
BOOST_AUTO_TEST_CASE(a_scriptsig_on_the_second_input_is_refused_at_relay)
{
    const CTransaction& first = coinbaseTxns[0];
    const CTransaction& second = coinbaseTxns[1];
    CMutableTransaction original;
    original.nVersion = 2;
    original.vin.push_back(CTxIn(COutPoint(first.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
    original.vin.push_back(CTxIn(COutPoint(second.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
    original.vout.push_back(CTxOut(first.vout[0].nValue + second.vout[0].nValue - FEE, coinbaseSpk));
    SignInput(original, 0, coinbaseSpk, first.vout[0].nValue);
    SignInput(original, 1, coinbaseSpk, second.vout[0].nValue);

    CMutableTransaction changed = original;
    changed.vin[1].scriptSig = AddedScriptSigs()[0];
    BOOST_CHECK_EQUAL(Verdict(changed), SCRIPTSIG);
    BOOST_CHECK_EQUAL(mempool.size(), 0u);
    BOOST_CHECK_EQUAL(Verdict(original), ACCEPTED);
}

// The rule is no rule on blocks. A block the case builds with a copy that
// carries a scriptSig connects and spends the output.
BOOST_AUTO_TEST_CASE(a_block_with_a_scriptsig_on_a_witness_spend_connects)
{
    CMutableTransaction changed = Fund(0, coinbaseSpk);
    changed.vin[0].scriptSig = AddedScriptSigs()[1];
    BOOST_CHECK(Connects({changed}));
    BOOST_CHECK(!Unspent(changed.vin[0].prevout));
    BOOST_CHECK(Unspent(COutPoint(changed.GetHash(), 0)));
}

// Where standardness is not required, as on testnet and regtest, neither
// rule applies: a copy with a scriptSig is accepted, and so is a spend whose
// script holds one hash opcode more than the limit.
BOOST_AUTO_TEST_CASE(neither_rule_applies_where_standardness_is_not_required)
{
    const CScript script = HashChain(LIMIT + 1);
    const CMutableTransaction funding = Confirmed(1, 6, script);

    ScopedRequireStandard off(false);
    CMutableTransaction changed = Fund(0, coinbaseSpk);
    changed.vin[0].scriptSig = AddedScriptSigs()[0];
    BOOST_CHECK_EQUAL(Verdict(changed), ACCEPTED);
    BOOST_CHECK_EQUAL(Verdict(SpendScript(funding, 6, script)), ACCEPTED);
}

// A script of version 6 and one of version 11, each with the limit of hash
// opcodes and with one more. Every script evaluates to true. Relay accepts
// the spend at the limit. It refuses the spend with one more as a
// non-standard witness, with no score and with the state marked as possible
// corruption, since the transaction id does not cover what the rule reads.
// A block the case builds with the refused spend connects.
BOOST_AUTO_TEST_CASE(a_script_with_more_hash_opcodes_than_the_limit_is_refused_at_relay_and_connects_in_a_block)
{
    BOOST_REQUIRE(fRequireStandard);
    size_t n = 0;
    for (int version : {6, 11}) {
        const CScript atTheLimit = HashChain(LIMIT);
        const CMutableTransaction fundedAtTheLimit = Confirmed(n++, version, atTheLimit);
        const std::string accepted = Verdict(SpendScript(fundedAtTheLimit, version, atTheLimit));
        BOOST_CHECK_MESSAGE(accepted == ACCEPTED, "version " << version << ", " << LIMIT << " hash opcodes: \"" << accepted << "\"");

        const CScript over = HashChain(LIMIT + 1);
        const CMutableTransaction fundedOver = Confirmed(n++, version, over);
        const CMutableTransaction spend = SpendScript(fundedOver, version, over);
        CValidationState state;
        const std::string verdict = Verdict(spend, state);
        BOOST_CHECK_MESSAGE(verdict == WITNESS_NONSTANDARD, "version " << version << ", " << LIMIT + 1 << " hash opcodes: \"" << verdict << "\"");
        int nDoS = -1;
        BOOST_CHECK(state.IsInvalid(nDoS));
        BOOST_CHECK_MESSAGE(nDoS == 0, "version " << version << ": score " << nDoS);
        BOOST_CHECK_MESSAGE(state.CorruptionPossible(), "version " << version << ": the state is not marked as possible corruption");

        BOOST_CHECK_MESSAGE(Connects({spend}), "version " << version << ": a block with the spend did not connect");
        BOOST_CHECK(!Unspent(COutPoint(fundedOver.GetHash(), 0)));
    }
}

// The count is over the whole script. A script whose hash opcode beyond the
// limit sits in a branch that does not run is refused at relay. A script at
// the limit that also pushes seventeen bytes of the opcode's value, and drops
// them, is accepted: a byte inside a push is no opcode.
BOOST_AUTO_TEST_CASE(the_count_takes_a_branch_that_does_not_run_and_leaves_out_the_bytes_of_a_push)
{
    BOOST_REQUIRE(fRequireStandard);
    CScript branch = HashChain(LIMIT);
    branch << OP_IF << OP_1 << OP_ELSE << OP_SHA256 << OP_ENDIF;
    const CMutableTransaction fundedBranch = Confirmed(0, 6, branch);
    BOOST_CHECK_EQUAL(Verdict(SpendScript(fundedBranch, 6, branch)), WITNESS_NONSTANDARD);
    BOOST_CHECK(Connects({SpendScript(fundedBranch, 6, branch)}));

    CScript pushed;
    pushed << valtype(LIMIT + 1, (unsigned char)OP_SHA256) << OP_DROP;
    pushed += HashChain(LIMIT);
    const CMutableTransaction fundedPushed = Confirmed(1, 6, pushed);
    BOOST_CHECK_EQUAL(Verdict(SpendScript(fundedPushed, 6, pushed)), ACCEPTED);
}

// The place of the scriptSig rule: before the rule on the form of the output
// an input spends and before the limits on the witness. A spend of a 20-byte
// program of version 6, a form Solver does not name, and a spend whose script
// is one hash opcode over the limit: each gets the later rule's reason with
// an empty scriptSig and the scriptSig rule's reason with one. The second has
// no mark of possible corruption then, which the later rule would set.
BOOST_AUTO_TEST_CASE(the_scriptsig_rule_answers_before_the_other_input_rules)
{
    BOOST_REQUIRE(fRequireStandard);
    const COutPoint seeded = SeedCoin(CScript() << OP_6 << valtype(20, 0x06), 10 * COIN, 0x61);
    CMutableTransaction spendShort;
    spendShort.nVersion = 2;
    spendShort.vin.push_back(CTxIn(seeded, CScript(), CTxIn::SEQUENCE_FINAL));
    spendShort.vout.push_back(CTxOut(10 * COIN - FEE, coinbaseSpk));
    spendShort.vin[0].scriptWitness.stack = {valtype(1, 0x00)};
    BOOST_CHECK_EQUAL(Verdict(spendShort), "bad-txns-nonstandard-inputs");
    spendShort.vin[0].scriptSig = AddedScriptSigs()[0];
    BOOST_CHECK_EQUAL(Verdict(spendShort), SCRIPTSIG);

    const CScript over = HashChain(LIMIT + 1);
    const CMutableTransaction funding = Confirmed(0, 6, over);
    CMutableTransaction spendOver = SpendScript(funding, 6, over);
    BOOST_CHECK_EQUAL(Verdict(spendOver), WITNESS_NONSTANDARD);
    spendOver.vin[0].scriptSig = AddedScriptSigs()[0];
    CValidationState state;
    BOOST_CHECK_EQUAL(Verdict(spendOver, state), SCRIPTSIG);
    BOOST_CHECK(!state.CorruptionPossible());
    BOOST_CHECK_EQUAL(mempool.size(), 0u);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(relay_witness_input_rules_policy_tests, PolicySetup)

// The scriptSig rule through its function. For an output of each witness
// version 0 to 16 and for a 20-byte program, an input with an empty scriptSig
// is outside the rule and one with a scriptSig is inside it, with a witness
// or without. An input that spends an output that is no witness program is
// outside it, and so is a coinbase. One input inside the rule is enough,
// whichever place it has among the inputs: the last, the first or one between.
BOOST_AUTO_TEST_CASE(the_scriptsig_rule_reads_the_output_an_input_spends_and_the_scriptsig_of_the_input)
{
    const CScript push00 = CScript() << valtype(1, 0x00);
    for (unsigned int out = 0; out <= SHORT_PROGRAM; ++out) {
        CMutableTransaction spend = SpendOf({out});
        BOOST_CHECK_MESSAGE(!SpendsWitnessProgramWithScriptSig(CTransaction(spend), view), "output " << out << ", an empty scriptSig");
        spend.vin[0].scriptWitness.stack = {valtype(1, 0x00)};
        BOOST_CHECK_MESSAGE(!SpendsWitnessProgramWithScriptSig(CTransaction(spend), view), "output " << out << ", an empty scriptSig and a witness");
        spend.vin[0].scriptSig = push00;
        BOOST_CHECK_MESSAGE(SpendsWitnessProgramWithScriptSig(CTransaction(spend), view), "output " << out << ", a scriptSig and a witness");
        spend.vin[0].scriptWitness.SetNull();
        BOOST_CHECK_MESSAGE(SpendsWitnessProgramWithScriptSig(CTransaction(spend), view), "output " << out << ", a scriptSig");
    }

    CMutableTransaction noProgram = SpendOf({NO_PROGRAM, 1});
    noProgram.vin[0].scriptSig = push00;
    BOOST_CHECK(!SpendsWitnessProgramWithScriptSig(CTransaction(noProgram), view));
    noProgram.vin[1].scriptSig = push00;
    BOOST_CHECK(SpendsWitnessProgramWithScriptSig(CTransaction(noProgram), view));

    // The first of two inputs carries the scriptSig and the last has none;
    // then the second of three.
    CMutableTransaction first = SpendOf({1, 2});
    first.vin[0].scriptSig = push00;
    BOOST_CHECK(SpendsWitnessProgramWithScriptSig(CTransaction(first), view));
    CMutableTransaction between = SpendOf({1, 2, 3});
    between.vin[1].scriptSig = push00;
    BOOST_CHECK(SpendsWitnessProgramWithScriptSig(CTransaction(between), view));

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << 1 << OP_0;
    coinbase.vout.push_back(CTxOut(COIN, CScript() << OP_1 << valtype(32, 0x01)));
    BOOST_REQUIRE(CTransaction(coinbase).IsCoinBase());
    BOOST_CHECK(!SpendsWitnessProgramWithScriptSig(CTransaction(coinbase), view));
}

// The limit through IsWitnessStandard, for versions 6 and 11: a script of
// the limit's number of OP_SHA256 is standard and one more is refused while
// the version's bit is set, and with the bit clear no limit is read. The
// limit is on the script of each input: two inputs at the limit are standard,
// and one input over it is refused, whichever of the two it is.
BOOST_AUTO_TEST_CASE(the_limit_is_read_for_versions_6_and_11_while_their_bit_is_set)
{
    BOOST_CHECK_EQUAL(MAX_STANDARD_SCRIPT_HASH_OPCODES, 16u);
    for (int version : {6, WITNESS_V11_VERSION}) {
        const valtype atTheLimit = ScriptItem(version, valtype(LIMIT, (unsigned char)OP_SHA256));
        const valtype over = ScriptItem(version, valtype(LIMIT + 1, (unsigned char)OP_SHA256));
        BOOST_CHECK_MESSAGE(Standard(version, atTheLimit, RUNNING), "version " << version << ", the limit");
        BOOST_CHECK_MESSAGE(!Standard(version, over, RUNNING), "version " << version << ", one more than the limit");
        BOOST_CHECK_MESSAGE(!Standard(version, over, WitnessVersionBit(version)), "version " << version << ", its bit alone");
        BOOST_CHECK_MESSAGE(Standard(version, over, RUNNING & ~WitnessVersionBit(version)), "version " << version << ", its bit clear");
    }

    const valtype trailer(1, 0x00);
    const valtype v6AtTheLimit = ScriptItem(6, valtype(LIMIT, (unsigned char)OP_SHA256));
    const valtype v11AtTheLimit = ScriptItem(WITNESS_V11_VERSION, valtype(LIMIT, (unsigned char)OP_SHA256));
    CMutableTransaction two = SpendOf({6, WITNESS_V11_VERSION});
    two.vin[0].scriptWitness.stack = {ITEM, v6AtTheLimit, trailer};
    two.vin[1].scriptWitness.stack = {ITEM, v11AtTheLimit, trailer};
    BOOST_CHECK_MESSAGE(IsWitnessStandard(CTransaction(two), view, RUNNING), "two inputs, each at the limit");
    two.vin[1].scriptWitness.stack[1] = ScriptItem(WITNESS_V11_VERSION, valtype(LIMIT + 1, (unsigned char)OP_SHA256));
    BOOST_CHECK_MESSAGE(!IsWitnessStandard(CTransaction(two), view, RUNNING), "the second input one over the limit");
    two.vin[1].scriptWitness.stack[1] = v11AtTheLimit;
    two.vin[0].scriptWitness.stack[1] = ScriptItem(6, valtype(LIMIT + 1, (unsigned char)OP_SHA256));
    BOOST_CHECK_MESSAGE(!IsWitnessStandard(CTransaction(two), view, RUNNING), "the first input one over the limit");

    // Two inputs of one version. The policy function reads the output and the
    // witness of each input, so the two inputs here name one output.
    for (unsigned int version : {6u, (unsigned int)WITNESS_V11_VERSION}) {
        const valtype atTheLimit = ScriptItem(version, valtype(LIMIT, (unsigned char)OP_SHA256));
        const valtype over = ScriptItem(version, valtype(LIMIT + 1, (unsigned char)OP_SHA256));
        CMutableTransaction same = SpendOf({version, version});
        same.vin[0].scriptWitness.stack = {ITEM, atTheLimit, trailer};
        same.vin[1].scriptWitness.stack = {ITEM, atTheLimit, trailer};
        BOOST_CHECK_MESSAGE(IsWitnessStandard(CTransaction(same), view, RUNNING), "two inputs of version " << version << ", each at the limit");
        same.vin[1].scriptWitness.stack[1] = over;
        BOOST_CHECK_MESSAGE(!IsWitnessStandard(CTransaction(same), view, RUNNING), "two inputs of version " << version << ", the second one over the limit");
        same.vin[1].scriptWitness.stack[1] = atTheLimit;
        same.vin[0].scriptWitness.stack[1] = over;
        BOOST_CHECK_MESSAGE(!IsWitnessStandard(CTransaction(same), view, RUNNING), "two inputs of version " << version << ", the first one over the limit");
    }
}

// Each of the five hash opcodes counts, in both versions: the limit's number
// of OP_SHA256 and one of the opcode is refused.
BOOST_AUTO_TEST_CASE(each_of_the_five_hash_opcodes_counts)
{
    for (int version : {6, WITNESS_V11_VERSION}) {
        for (opcodetype op : {OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256}) {
            valtype script(LIMIT, (unsigned char)OP_SHA256);
            script.push_back((unsigned char)op);
            BOOST_CHECK_MESSAGE(!Standard(version, ScriptItem(version, script), RUNNING), "version " << version << ", " << GetOpName(op));
        }
        // The opcodes on either side of the five do not count.
        for (opcodetype op : {OP_WITHIN, OP_CODESEPARATOR}) {
            valtype script(LIMIT, (unsigned char)OP_SHA256);
            script.push_back((unsigned char)op);
            BOOST_CHECK_MESSAGE(Standard(version, ScriptItem(version, script), RUNNING), "version " << version << ", " << GetOpName(op));
        }
    }
}

// What the count leaves out. The bytes of a push. Whatever follows the place
// where the script stops decoding: the script check refuses such a script
// with a reason of its own. A committed item of version 11 whose sub-version
// is another than the script's, which is no script. An input of another
// witness version, whatever its witness holds.
BOOST_AUTO_TEST_CASE(what_the_count_leaves_out)
{
    for (int version : {6, WITNESS_V11_VERSION}) {
        valtype pushed(LIMIT, (unsigned char)OP_SHA256);
        pushed.push_back(0x02);
        pushed.push_back((unsigned char)OP_SHA256);
        pushed.push_back((unsigned char)OP_SHA256);
        BOOST_CHECK_MESSAGE(Standard(version, ScriptItem(version, pushed), RUNNING), "version " << version << ", two bytes of a push");

        valtype cutShort(LIMIT, (unsigned char)OP_SHA256);
        cutShort.push_back(0x05);
        cutShort.push_back((unsigned char)OP_SHA256);
        BOOST_CHECK_MESSAGE(Standard(version, ScriptItem(version, cutShort), RUNNING), "version " << version << ", a push cut short");

        valtype overThenCutShort(LIMIT + 1, (unsigned char)OP_SHA256);
        overThenCutShort.push_back(0x05);
        BOOST_CHECK_MESSAGE(!Standard(version, ScriptItem(version, overThenCutShort), RUNNING), "version " << version << ", one more than the limit before a push cut short");
    }

    valtype otherSubversion(1, 0x01);
    otherSubversion.insert(otherSubversion.end(), LIMIT + 1, (unsigned char)OP_SHA256);
    BOOST_CHECK(Standard(WITNESS_V11_VERSION, otherSubversion, RUNNING));
    BOOST_CHECK(Standard(WITNESS_V11_VERSION, valtype(), RUNNING));

    const valtype over(LIMIT + 1, (unsigned char)OP_SHA256);
    for (unsigned int version : {1u, 5u, 7u, 8u, 9u, 12u})
        BOOST_CHECK_MESSAGE(Standard(version, over, ~(WitnessVersionMask)0), "version " << version);
    BOOST_CHECK(Standard(SHORT_PROGRAM, over, ~(WitnessVersionMask)0));
}

BOOST_AUTO_TEST_SUITE_END()
