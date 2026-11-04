// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// v6_checksequence_bip112_tests.cpp — OP_CHECKSEQUENCEVERIFY inside a witness
// v6 (P2WSH-Dilithium) witnessScript is satisfied only by a relative lock that
// BIP68 enforces.
//
// BIP68 enforces a relative lock only on a transaction of version 2 or higher,
// and only on an input whose sequence number does not carry the disable flag.
// BIP112 therefore makes CHECKSEQUENCEVERIFY fail on a transaction below
// version 2 and on a disable-flag input: the sequence bits it would otherwise
// compare carry no consensus meaning there, so a script satisfied in either
// state would have no wait behind it. TransactionSignatureChecker::CheckSequence
// carries both rules.
//
// Two suites. The first drives <n> CHECKSEQUENCEVERIFY through VerifyScript
// with a transaction checker in every transaction state the rule names, and
// pins the shipped eLTOO template's settlement leg. The second funds a delayed
// v6 output in a mined regtest block and spends it at once with a version-1
// transaction and with a disable-flag input, which the mempool and
// ConnectBlock must both refuse; the version-2 spend is held by BIP68 until the
// delay has passed and accepted after it.

#include "chainparams.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/dilithium_chain_setup.h"
#include "test/test_bitcoin.h"
#include "txmempool.h"
#include "validation.h"
#include "versionbits.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

typedef std::vector<unsigned char> valtype;

const uint32_t DISABLE = CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG;
const uint32_t BY_TIME = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;

CScript V6ProgramFor(const CScript& witnessScript)
{
    uint256 h;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(h.begin());
    CScript spk;
    spk << OP_6 << valtype(h.begin(), h.end());
    return spk;
}

//! <n> CHECKSEQUENCEVERIFY DROP 1: the delay with nothing behind it.
CScript DelayOf(int64_t n)
{
    return CScript() << CScriptNum(n) << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_1;
}

//! A one-input spending transaction in the state the rule reads.
CMutableTransaction SpendWith(int32_t nVersion, uint32_t nSequence, uint32_t nLockTime = 0)
{
    CMutableTransaction tx;
    tx.nVersion = nVersion;
    tx.nLockTime = nLockTime;
    tx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0), CScript(), nSequence));
    tx.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
    return tx;
}

//! The verdict of VerifyScript on the v6 program of `ws` spent by `mtx`, with
//! the witness [items...] [witnessScript] [0x00-prefixed trailer].
ScriptError VerdictFor(const CScript& ws, const CMutableTransaction& mtx, unsigned int flags,
                       const std::vector<valtype>& items = std::vector<valtype>())
{
    CScriptWitness w;
    for (const valtype& v : items)
        w.stack.push_back(v);
    w.stack.push_back(valtype(ws.begin(), ws.end()));
    w.stack.push_back(valtype(1313, 0x00));
    const CTransaction tx(mtx);
    TransactionSignatureChecker checker(&tx, 0, COIN);
    ScriptError serr = SCRIPT_ERR_OK;
    VerifyScript(CScript(), V6ProgramFor(ws), &w, flags, checker, &serr);
    return serr;
}

std::string Verdict(ScriptError e) { return std::string(ScriptErrorString(e)); }

const unsigned int P2WSH = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2WSH_DILITHIUM;

//! Every handler live: the three swap flags, the restored set and the
//! flag-gated covenant opcodes.
const unsigned int FULL = P2WSH | SCRIPT_VERIFY_DILITHIUM_KEYHASH | SCRIPT_VERIFY_V6_CONTROLFLOW |
                          SCRIPT_VERIFY_SCRIPT_RESTORE | SCRIPT_VERIFY_CTV | SCRIPT_VERIFY_CSFS |
                          SCRIPT_VERIFY_APO;

} // namespace

BOOST_FIXTURE_TEST_SUITE(v6_checksequence_bip112_tests, BasicTestingSetup)

// A version-2 transaction whose input's sequence encodes the wait satisfies the
// operand; one short, or of the other type, does not. Bits outside the mask are
// ignored, as BIP68 ignores them.
BOOST_AUTO_TEST_CASE(a_version_2_transaction_satisfies_the_operand_its_sequence_encodes)
{
    const CScript byHeight = DelayOf(20);
    BOOST_CHECK_EQUAL(VerdictFor(byHeight, SpendWith(2, 20), FULL), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(byHeight, SpendWith(2, 0xffff), FULL), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(byHeight, SpendWith(2, 20 | (1u << 20)), FULL), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(byHeight, SpendWith(2, 19), FULL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(VerdictFor(byHeight, SpendWith(2, BY_TIME | 20), FULL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);

    const CScript byTime = DelayOf(BY_TIME | 20);
    BOOST_CHECK_EQUAL(VerdictFor(byTime, SpendWith(2, BY_TIME | 20), FULL), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(byTime, SpendWith(2, BY_TIME | 19), FULL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(VerdictFor(byTime, SpendWith(2, 20), FULL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

// A transaction below version 2 satisfies no operand, whatever its input's
// sequence encodes: BIP68 enforces nothing on it. The comparison is unsigned,
// as BIP68's is, so a negative version is enforced and satisfies the operand.
BOOST_AUTO_TEST_CASE(a_transaction_below_version_2_satisfies_nothing)
{
    const CScript ws = DelayOf(20);
    BOOST_CHECK_EQUAL(VerdictFor(ws, SpendWith(1, 20), FULL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(VerdictFor(ws, SpendWith(1, 0xffff), FULL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(VerdictFor(ws, SpendWith(0, 20), FULL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(VerdictFor(ws, SpendWith(3, 20), FULL), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(ws, SpendWith(-1, 20), FULL), SCRIPT_ERR_OK);
}

// An input whose sequence carries the disable flag satisfies no operand: BIP68
// skips it. A final sequence is the special case.
BOOST_AUTO_TEST_CASE(a_disable_flag_input_satisfies_nothing)
{
    const CScript ws = DelayOf(20);
    BOOST_CHECK_EQUAL(VerdictFor(ws, SpendWith(2, DISABLE | 20), FULL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(VerdictFor(ws, SpendWith(2, DISABLE | 0xffff), FULL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(VerdictFor(DelayOf(BY_TIME | 20), SpendWith(2, DISABLE | BY_TIME | 20), FULL),
                      SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(VerdictFor(ws, SpendWith(2, CTxIn::SEQUENCE_FINAL), FULL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(VerdictFor(ws, SpendWith(2, 0xfffffffe), FULL), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

// The operand-side rules do not read the transaction and are unchanged: an
// operand with the disable flag set is a NOP (BIP112 extensibility) and a
// negative operand fails in the handler.
BOOST_AUTO_TEST_CASE(the_operand_side_rules_are_unchanged)
{
    const CScript nop = DelayOf(static_cast<int64_t>(DISABLE | 20));
    BOOST_CHECK_EQUAL(VerdictFor(nop, SpendWith(1, 0), FULL), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(nop, SpendWith(2, CTxIn::SEQUENCE_FINAL), FULL), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(nop, SpendWith(1, 0), FULL | SCRIPT_VERIFY_MINIMALDATA), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(DelayOf(-1), SpendWith(2, 20), FULL), SCRIPT_ERR_NEGATIVE_LOCKTIME);
}

// The verdict is the same in every flag state in which the handler runs, and
// unchanged (success) with v6 dormant.
BOOST_AUTO_TEST_CASE(the_verdict_is_the_same_in_every_flag_state_in_which_the_handler_runs)
{
    const CScript ws = DelayOf(20);
    const unsigned int states[] = {
        P2WSH | SCRIPT_VERIFY_V6_CONTROLFLOW,
        FULL,
        FULL & ~SCRIPT_VERIFY_SCRIPT_RESTORE,
        FULL | SCRIPT_VERIFY_MINIMALIF | SCRIPT_VERIFY_CLEANSTACK |
            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS | SCRIPT_VERIFY_MINIMALDATA,
    };
    for (unsigned int flags : states) {
        const ScriptError v1 = VerdictFor(ws, SpendWith(1, 20), flags);
        const ScriptError disabled = VerdictFor(ws, SpendWith(2, DISABLE | 20), flags);
        const ScriptError v2 = VerdictFor(ws, SpendWith(2, 20), flags);
        BOOST_CHECK_MESSAGE(v1 == SCRIPT_ERR_UNSATISFIED_LOCKTIME,
            "flags=" << flags << ": version 1 got " << Verdict(v1));
        BOOST_CHECK_MESSAGE(disabled == SCRIPT_ERR_UNSATISFIED_LOCKTIME,
            "flags=" << flags << ": the disable-flag input got " << Verdict(disabled));
        BOOST_CHECK_MESSAGE(v2 == SCRIPT_ERR_OK,
            "flags=" << flags << ": version 2 with the sequence set got " << Verdict(v2));
    }
    BOOST_CHECK_EQUAL(VerdictFor(ws, SpendWith(1, 20), SCRIPT_VERIFY_WITNESS), SCRIPT_ERR_OK);
}

// The shipped eLTOO template (lightning_script_tests::b1_script_vectors). Its
// settlement leg with version 2 and sequence 288 passes the delay and reaches
// the keyhash checks; below version 2, with the disable flag or one block
// short it stops at the delay. The update leg's absolute lock does not read
// the version.
BOOST_AUTO_TEST_CASE(the_shipped_eltoo_template_settlement_leg)
{
    const valtype khAu(32, 0x11), khBu(32, 0x22), khAs(32, 0x33), khBs(32, 0x44);
    CScript eltoo;
    eltoo << OP_IF
            << CScriptNum(600001) << OP_CHECKLOCKTIMEVERIFY << OP_DROP
            << khBu << OP_CHECKDILITHIUMKEYHASH << khAu << OP_CHECKDILITHIUMKEYHASH << OP_1
          << OP_ELSE
            << CScriptNum(288) << OP_CHECKSEQUENCEVERIFY << OP_DROP
            << khBs << OP_CHECKDILITHIUMKEYHASH << khAs << OP_CHECKDILITHIUMKEYHASH << OP_1
          << OP_ENDIF;
    const std::vector<valtype> settle(1, valtype());         // the ELSE branch
    const std::vector<valtype> update(1, valtype(1, 0x01));  // the IF branch

    // With no key item on the stack, the keyhash check's stack read is where
    // the leg stops once the delay has passed.
    ScriptError v = VerdictFor(eltoo, SpendWith(2, 288), FULL, settle);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_INVALID_STACK_OPERATION,
        "settlement with version 2 and sequence 288 must pass the delay and stop at the keyhash check; got " << Verdict(v));
    BOOST_CHECK_EQUAL(VerdictFor(eltoo, SpendWith(1, 288), FULL, settle), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(VerdictFor(eltoo, SpendWith(2, DISABLE | 288), FULL, settle), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK_EQUAL(VerdictFor(eltoo, SpendWith(2, 287), FULL, settle), SCRIPT_ERR_UNSATISFIED_LOCKTIME);

    v = VerdictFor(eltoo, SpendWith(1, 0xfffffffe, 600001), FULL, update);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_INVALID_STACK_OPERATION,
        "the update leg with the height reached must pass the absolute lock and stop at the keyhash check; got " << Verdict(v));
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// The chain path: a delayed v6 output funded in a mined block, spent at once
// with a version-1 transaction and with a disable-flag input, then with a
// version-2 transaction before and after the delay.
// ---------------------------------------------------------------------------
BOOST_FIXTURE_TEST_SUITE(v6_checksequence_bip112_chain_tests, DilithiumChainSetup)

BOOST_AUTO_TEST_CASE(a_delayed_v6_output_is_held_at_relay_and_in_a_block)
{
    const int DELAY = 20;
    const CScript ws = DelayOf(DELAY);  // the settlement delay without the keys
    const CScript delayedSpk = V6ProgramFor(ws);

    // F: coinbase[0] to the delayed output, mined.
    const CAmount cbValue = coinbaseTxns[0].vout[0].nValue;
    const CAmount FEE = COIN;
    BOOST_REQUIRE(cbValue > 3 * FEE);
    CMutableTransaction F;
    F.nVersion = 2;
    F.vin.push_back(CTxIn(COutPoint(coinbaseTxns[0].GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
    F.vout.push_back(CTxOut(cbValue - FEE, delayedSpk));
    SignInput(F, 0, coinbaseSpk, cbValue);
    const CBlock bF = CreateAndProcessBlock(std::vector<CMutableTransaction>(1, F), coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == bF.GetHash(), "the funding block must connect");
    const int fundedAt = chainActive.Height();
    // The block path runs BIP68 only where the CSV deployment is ACTIVE. On
    // regtest it is not under the default block version, which carries no
    // version-bit signal, so a block there enforces the opcode's rule alone.
    bool csvActive;
    {
        LOCK(cs_main);
        const ThresholdState csv = VersionBitsState(chainActive.Tip(), Params().GetConsensus(fundedAt),
                                                    Consensus::DEPLOYMENT_CSV, versionbitscache);
        csvActive = (csv == THRESHOLD_ACTIVE);
        BOOST_TEST_MESSAGE("DEPLOYMENT_CSV state at the funding tip: " << csv
            << " (" << THRESHOLD_ACTIVE << " is ACTIVE)");
    }

    // S: spends F:0 to the coinbase key. Witness: the witnessScript and a
    // 0x00-prefixed trailer; the script needs no item.
    auto spend = [&](int32_t nVersion, uint32_t nSequence) {
        CMutableTransaction S;
        S.nVersion = nVersion;
        S.vin.push_back(CTxIn(COutPoint(F.GetHash(), 0), CScript(), nSequence));
        S.vout.push_back(CTxOut(cbValue - 2 * FEE, coinbaseSpk));
        CScriptWitness w;
        w.stack.push_back(valtype(ws.begin(), ws.end()));
        w.stack.push_back(valtype(1313, 0x00));
        S.vin[0].scriptWitness = w;
        return S;
    };
    // The relay verdict: the reject reason, or "" when accepted. The mempool is
    // emptied after each try, so every spend of the output is judged on its own.
    auto relay = [&](const CMutableTransaction& S) -> std::string {
        LOCK(cs_main);
        CValidationState st;
        const bool ok = AcceptToMemoryPool(mempool, st, MakeTransactionRef(S), false, nullptr, nullptr, true, 0);
        const std::string reason = ok ? std::string() : FormatStateMessage(st);
        mempool.clear();
        return reason;
    };
    auto one = [](const CMutableTransaction& S) { return std::vector<CMutableTransaction>(1, S); };
    const std::string unsatisfied = ScriptErrorString(SCRIPT_ERR_UNSATISFIED_LOCKTIME);

    // Version 1, the sequence encoding the delay: BIP68 enforces nothing on it.
    const CMutableTransaction S1 = spend(1, DELAY);
    std::string r = relay(S1);
    BOOST_CHECK_MESSAGE(r.find(unsatisfied) != std::string::npos,
        "a version-1 spend of the delayed output must be refused at relay with the lock named; got: "
        << (r.empty() ? std::string("accepted") : r));
    BOOST_CHECK_MESSAGE(!BlockIsValid(one(S1)), "a block holding the version-1 spend must fail ConnectBlock");

    // Version 2, the disable flag on the input: BIP68 skips the input.
    const CMutableTransaction S2 = spend(2, DISABLE | DELAY);
    r = relay(S2);
    BOOST_CHECK_MESSAGE(r.find(unsatisfied) != std::string::npos,
        "a disable-flag spend of the delayed output must be refused at relay with the lock named; got: "
        << (r.empty() ? std::string("accepted") : r));
    BOOST_CHECK_MESSAGE(!BlockIsValid(one(S2)), "a block holding the disable-flag spend must fail ConnectBlock");

    // Version 2, the sequence encoding the delay, at the funding tip: held by
    // BIP68 at relay until the delay has passed.
    const CMutableTransaction S3 = spend(2, DELAY);
    r = relay(S3);
    BOOST_CHECK_MESSAGE(r.find("non-BIP68-final") != std::string::npos,
        "the version-2 spend before the delay must be held by BIP68 at relay; got: "
        << (r.empty() ? std::string("accepted") : r));

    // The same spend in a block at the funding tip is held only where the block
    // path runs BIP68. Either way the two refusals above are the script's: the
    // same output, witness and tip, with only the version and the sequence
    // differing.
    BOOST_CHECK_EQUAL(BlockIsValid(one(S3)), !csvActive);

    // An empty block on the same tip connects: the refusals are the spends'.
    BOOST_CHECK(BlockIsValid(std::vector<CMutableTransaction>()));

    // The delay: BIP68 admits the spend into the block at height fundedAt +
    // DELAY, which the mempool evaluates once the tip is one below it. One
    // block earlier the spend is still held.
    for (int i = 0; i < DELAY - 2; ++i)
        CreateAndProcessBlock(std::vector<CMutableTransaction>(), coinbaseSpk);
    BOOST_REQUIRE_EQUAL(chainActive.Height(), fundedAt + DELAY - 2);
    r = relay(S3);
    BOOST_CHECK_MESSAGE(r.find("non-BIP68-final") != std::string::npos,
        "one block before the delay the version-2 spend must still be held at relay; got: "
        << (r.empty() ? std::string("accepted") : r));
    CreateAndProcessBlock(std::vector<CMutableTransaction>(), coinbaseSpk);
    BOOST_REQUIRE_EQUAL(chainActive.Height(), fundedAt + DELAY - 1);

    // After the delay: the version-2 spend is accepted at relay and valid in a
    // block; the two others stay refused, since no wait satisfies them.
    r = relay(S3);
    BOOST_CHECK_MESSAGE(r.empty(), "the version-2 spend after the delay must be accepted at relay; got: " << r);
    BOOST_CHECK_MESSAGE(BlockIsValid(one(S3)), "a block holding the version-2 spend after the delay must connect");
    r = relay(S1);
    BOOST_CHECK_MESSAGE(r.find(unsatisfied) != std::string::npos,
        "the version-1 spend stays refused after the delay; got: " << (r.empty() ? std::string("accepted") : r));
    BOOST_CHECK_MESSAGE(!BlockIsValid(one(S1)), "a block holding the version-1 spend after the delay must fail ConnectBlock");
    r = relay(S2);
    BOOST_CHECK_MESSAGE(r.find(unsatisfied) != std::string::npos,
        "the disable-flag spend stays refused after the delay; got: " << (r.empty() ? std::string("accepted") : r));
    BOOST_CHECK_MESSAGE(!BlockIsValid(one(S2)), "a block holding the disable-flag spend after the delay must fail ConnectBlock");
}

BOOST_AUTO_TEST_SUITE_END()
