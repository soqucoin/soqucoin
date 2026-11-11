// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// v6_witness_script_opcode_set_tests.cpp — a P2WSH-Dilithium (witness v6)
// witnessScript may carry only the opcodes v6 EvalScript executes.
//
// EvalScript dispatches through an if-chain with no terminal else, so a byte
// no branch matches returns with the stack untouched. Inside a v6 witnessScript
// that would make every unhandled opcode a silent no-op, and a script's
// meaning would depend on which bytes are ignored. The pre-scan in
// VerifyScript's v6 branch therefore admits pushes and the handled set
// and refuses every other byte with SCRIPT_ERR_DISALLOWED_OPCODE before
// execution, in every branch and in every flag state in which the v6 branch
// runs. The set is closed: admitting a byte later would be a loosening against
// the release that refused it (doc/specifications/WITNESS_VERSION_FORK_CLASS.md
// §3a), so a new opcode goes to a new witness version.
//
// Two suites. The first walks every opcode byte at the VerifyScript level and
// pins the set. The second drives a Bitcoin-shaped HTLC (HASH160 hashlock,
// CHECKSIG claim) through a real regtest chain: funded into a v6 output in a
// mined block, then spent with no preimage and no signature, which the mempool
// and ConnectBlock must both refuse.

#include "chainparams.h"
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

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

typedef std::vector<unsigned char> valtype;

CScript V6ProgramFor(const CScript& witnessScript)
{
    uint256 h;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(h.begin());
    CScript spk;
    spk << OP_6 << valtype(h.begin(), h.end());
    return spk;
}

//! v6 witness layout: [evaluation items...] [witnessScript] [0x00-prefixed trailer].
ScriptError VerdictFor(const CScript& witnessScript, unsigned int flags,
                       const std::vector<valtype>& items = std::vector<valtype>())
{
    CScriptWitness w;
    for (const valtype& v : items)
        w.stack.push_back(v);
    w.stack.push_back(valtype(witnessScript.begin(), witnessScript.end()));
    w.stack.push_back(valtype(1313, 0x00));
    BaseSignatureChecker checker;
    ScriptError serr = SCRIPT_ERR_OK;
    VerifyScript(CScript(), V6ProgramFor(witnessScript), &w, flags, checker, &serr);
    return serr;
}

const unsigned int P2WSH = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2WSH_DILITHIUM;

//! Every handler live: the three swap flags, the restored set (set in every
//! block) and the flag-gated covenant opcodes.
const unsigned int FULL = P2WSH | SCRIPT_VERIFY_DILITHIUM_KEYHASH | SCRIPT_VERIFY_V6_CONTROLFLOW |
                          SCRIPT_VERIFY_SCRIPT_RESTORE | SCRIPT_VERIFY_CTV | SCRIPT_VERIFY_CSFS |
                          SCRIPT_VERIFY_APO;

//! The set, transcribed from IsWitnessV6ScriptOpcode in script/interpreter.cpp.
//! Pushes (0x00 to OP_PUSHDATA4, OP_1 to OP_16) are checked separately.
const opcodetype SET[] = {
    OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF,
    OP_DROP, OP_SIZE, OP_EQUAL, OP_EQUALVERIFY, OP_SHA256,
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY,
    OP_CHECKDILITHIUMKEYHASH,
    OP_CHECKTEMPLATEVERIFY, OP_CHECKSIGFROMSTACK,
    OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT,
    OP_AND, OP_OR, OP_XOR, OP_MUL, OP_DIV, OP_MOD,
};

//! Refused by the asset and attestation ban with BAD_OPCODE, unchanged
//! (v6_asset_opcode_ban_tests.cpp).
const opcodetype ASSET[] = {
    OP_USDSOQ_MINT, OP_USDSOQ_BURN, OP_USDSOQ_FREEZE, OP_USDSOQ_ROTATE,
    OP_SOQUOBSCURA_RANGEPROOF, OP_CHECKFOLDPROOF, OP_CHECKPATAGG,
};

bool IsPush(int b) { return b <= OP_PUSHDATA4 || (b >= OP_1 && b <= OP_16); }
bool InSet(int b) { for (opcodetype op : SET) if (op == b) return true; return false; }
bool InAsset(int b) { for (opcodetype op : ASSET) if (op == b) return true; return false; }

std::string Verdict(ScriptError e) { return std::string(ScriptErrorString(e)); }

} // namespace

BOOST_FIXTURE_TEST_SUITE(v6_witness_script_opcode_set_tests, BasicTestingSetup)

// Every non-push byte (0x4f, 0x50 and everything above OP_16), alone and after
// an innocuous prefix. A member of the set reaches its handler, which objects
// to the empty stack with an error of its own; anything else is refused by the
// scan before execution.
BOOST_AUTO_TEST_CASE(every_byte_outside_the_set_is_refused_before_execution)
{
    int refused = 0, handled = 0;
    for (int b = 0; b <= 0xff; ++b) {
        if (IsPush(b))
            continue;
        const opcodetype op = static_cast<opcodetype>(b);
        const ScriptError alone = VerdictFor(CScript() << op, FULL);
        if (InAsset(b)) {
            const ScriptError after = VerdictFor(CScript() << OP_TRUE << op, FULL);
            BOOST_CHECK_MESSAGE(alone == SCRIPT_ERR_BAD_OPCODE && after == SCRIPT_ERR_BAD_OPCODE,
                GetOpName(op) << " keeps BAD_OPCODE under the asset ban; got "
                              << Verdict(alone) << " / " << Verdict(after));
        } else if (InSet(b)) {
            ++handled;
            BOOST_CHECK_MESSAGE(alone != SCRIPT_ERR_DISALLOWED_OPCODE && alone != SCRIPT_ERR_OK &&
                                alone != SCRIPT_ERR_EVAL_FALSE,
                GetOpName(op) << " is in the set and must reach its handler; got " << Verdict(alone));
        } else {
            ++refused;
            const ScriptError after = VerdictFor(CScript() << OP_TRUE << op, FULL);
            BOOST_CHECK_MESSAGE(alone == SCRIPT_ERR_DISALLOWED_OPCODE,
                GetOpName(op) << " (0x" << std::hex << b << std::dec
                              << ") is outside the set and must be refused; got " << Verdict(alone));
            BOOST_CHECK_MESSAGE(after == SCRIPT_ERR_DISALLOWED_OPCODE,
                GetOpName(op) << " after a prefix must be refused: the whole script is scanned; got "
                              << Verdict(after));
        }
    }
    BOOST_CHECK_EQUAL(handled, (int)(sizeof(SET) / sizeof(SET[0])));
    // 256 bytes, less 95 pushes (79 from 0x00 to 0x4e, 16 from 0x51 to 0x60),
    // less the set, less the seven asset bytes.
    BOOST_CHECK_EQUAL(refused, 256 - 95 - (int)(sizeof(SET) / sizeof(SET[0])) - 7);
}

// Pushes of every encoding pass the scan, and the bytes of a refused opcode
// inside push data are data.
BOOST_AUTO_TEST_CASE(pushes_of_every_form_pass_the_scan)
{
    BOOST_CHECK_EQUAL(VerdictFor(CScript() << valtype(10, 0x01) << OP_DROP << OP_1, FULL), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(CScript() << valtype(100, 0x01) << OP_DROP << OP_1, FULL), SCRIPT_ERR_OK);  // PUSHDATA1
    BOOST_CHECK_EQUAL(VerdictFor(CScript() << valtype(300, 0x01) << OP_DROP << OP_1, FULL), SCRIPT_ERR_OK);  // PUSHDATA2
    {
        // PUSHDATA4 of one byte, which CScript's operator<< never emits.
        const unsigned char raw[] = {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, OP_CHECKSIG};
        CScript s(raw, raw + sizeof(raw));
        s << OP_DROP << OP_1;
        BOOST_CHECK_EQUAL(VerdictFor(s, FULL), SCRIPT_ERR_OK);
    }
    BOOST_CHECK_EQUAL(VerdictFor(CScript() << OP_0 << OP_DROP << OP_1, FULL), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(CScript() << OP_16 << OP_DROP << OP_1, FULL), SCRIPT_ERR_OK);
    {
        valtype data;
        data.push_back(OP_CHECKSIG);
        data.push_back(OP_HASH160);
        data.push_back(OP_DUP);
        data.push_back(OP_RIPEMD160);
        BOOST_CHECK_EQUAL(VerdictFor(CScript() << data, FULL), SCRIPT_ERR_OK);
    }
}

// The scan covers branches not taken: a refused byte behind a false IF is
// still refused.
BOOST_AUTO_TEST_CASE(a_refused_opcode_in_a_branch_not_taken_is_refused)
{
    const CScript s = CScript() << OP_0 << OP_IF << OP_CHECKSIG << OP_ENDIF << OP_1;
    BOOST_CHECK_EQUAL(VerdictFor(s, FULL), SCRIPT_ERR_DISALLOWED_OPCODE);
}

// Once the v6 branch runs, the verdict does not depend on the other flags;
// with the v6 flag clear the dormant posture is unchanged.
BOOST_AUTO_TEST_CASE(the_verdict_is_the_same_in_every_flag_state_in_which_v6_runs)
{
    const CScript s = CScript() << OP_CHECKSIG;
    const unsigned int states[] = {
        P2WSH,
        P2WSH | SCRIPT_VERIFY_DILITHIUM_KEYHASH,
        P2WSH | SCRIPT_VERIFY_V6_CONTROLFLOW,
        P2WSH | SCRIPT_VERIFY_SCRIPT_RESTORE,
        FULL,
        FULL & ~SCRIPT_VERIFY_SCRIPT_RESTORE,
        FULL | SCRIPT_VERIFY_MINIMALIF | SCRIPT_VERIFY_CLEANSTACK |
            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS | SCRIPT_VERIFY_MINIMALDATA,
    };
    for (unsigned int flags : states) {
        BOOST_CHECK_MESSAGE(VerdictFor(s, flags) == SCRIPT_ERR_DISALLOWED_OPCODE,
            "flags=" << flags << ": got " << Verdict(VerdictFor(s, flags)));
    }
    BOOST_CHECK_EQUAL(VerdictFor(s, SCRIPT_VERIFY_WITNESS), SCRIPT_ERR_OK);
}

// The members of the set still execute as before: a satisfied hashlock.
BOOST_AUTO_TEST_CASE(a_member_of_the_set_executes_after_the_scan)
{
    const valtype preimage(32, 0x07);
    valtype H(32);
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(H.data());
    const CScript s = CScript() << OP_SHA256 << H << OP_EQUAL;
    BOOST_CHECK_EQUAL(VerdictFor(s, FULL, std::vector<valtype>(1, preimage)), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(VerdictFor(s, FULL, std::vector<valtype>(1, valtype(32, 0x08))), SCRIPT_ERR_EVAL_FALSE);
}

// The two shipped templates (lightning_script_tests::b1_script_vectors) are
// inside the set: the scan admits them and execution begins.
BOOST_AUTO_TEST_CASE(the_shipped_templates_are_inside_the_set)
{
    const valtype H(32, 0xab), khPayee(32, 0x55), khPayer(32, 0x66);
    CScript htlc;
    htlc << OP_IF
           << OP_SHA256 << H << OP_EQUALVERIFY << khPayee << OP_CHECKDILITHIUMKEYHASH << OP_1
         << OP_ELSE
           << CScriptNum(500) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << khPayer << OP_CHECKDILITHIUMKEYHASH << OP_1
         << OP_ENDIF;
    const valtype khAu(32, 0x11), khBu(32, 0x22), khAs(32, 0x33), khBs(32, 0x44);
    CScript eltoo;
    eltoo << OP_IF
            << CScriptNum(600001) << OP_CHECKLOCKTIMEVERIFY << OP_DROP
            << khBu << OP_CHECKDILITHIUMKEYHASH << khAu << OP_CHECKDILITHIUMKEYHASH << OP_1
          << OP_ELSE
            << CScriptNum(288) << OP_CHECKSEQUENCEVERIFY << OP_DROP
            << khBs << OP_CHECKDILITHIUMKEYHASH << khAs << OP_CHECKDILITHIUMKEYHASH << OP_1
          << OP_ENDIF;
    for (const CScript* s : {&htlc, &eltoo}) {
        const ScriptError v = VerdictFor(*s, FULL);
        BOOST_CHECK_MESSAGE(v != SCRIPT_ERR_DISALLOWED_OPCODE && v != SCRIPT_ERR_BAD_OPCODE,
            "a shipped template must pass the scan; got " << Verdict(v));
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// The chain path: a Bitcoin-shaped HTLC funded into v6 in a mined block, then
// spent with no preimage and no signature.
// ---------------------------------------------------------------------------
BOOST_FIXTURE_TEST_SUITE(v6_witness_script_opcode_set_chain_tests, DilithiumChainSetup)

BOOST_AUTO_TEST_CASE(a_bitcoin_shaped_htlc_in_v6_is_refused_at_relay_and_in_a_block)
{
    // The template a wallet built for Bitcoin script carries: a HASH160
    // hashlock, a CHECKSIG claim, a CLTV refund, 33-byte key stand-ins.
    const valtype h160(20, 0x11);
    const valtype claimKey(33, 0x02);
    const valtype refundKey(33, 0x03);
    CScript ws;
    ws << OP_IF
         << OP_HASH160 << h160 << OP_EQUALVERIFY << claimKey << OP_CHECKSIG
       << OP_ELSE
         << CScriptNum(500) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << refundKey << OP_CHECKSIG
       << OP_ENDIF;
    const CScript htlcSpk = V6ProgramFor(ws);

    // F: coinbase[0] to the v6 HTLC, mined.
    const CAmount cbValue = coinbaseTxns[0].vout[0].nValue;
    const CAmount FEE = COIN;
    BOOST_REQUIRE(cbValue > 3 * FEE);
    CMutableTransaction F;
    F.nVersion = 2;
    F.vin.push_back(CTxIn(COutPoint(coinbaseTxns[0].GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
    F.vout.push_back(CTxOut(cbValue - FEE, htlcSpk));
    SignInput(F, 0, coinbaseSpk, cbValue);
    const CBlock bF = CreateAndProcessBlock(std::vector<CMutableTransaction>(1, F), coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == bF.GetHash(), "the funding block must connect");

    // S: spends the HTLC. Witness: the committed hash in place of a preimage,
    // a true selector, the witnessScript, a 0x00-prefixed trailer. No
    // signature anywhere.
    CMutableTransaction S;
    S.nVersion = 2;
    S.vin.push_back(CTxIn(COutPoint(F.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
    S.vout.push_back(CTxOut(cbValue - 2 * FEE, coinbaseSpk));
    {
        CScriptWitness w;
        w.stack.push_back(h160);
        w.stack.push_back(valtype(1, 0x01));
        w.stack.push_back(valtype(ws.begin(), ws.end()));
        w.stack.push_back(valtype(1313, 0x00));
        S.vin[0].scriptWitness = w;
    }

    // Relay: refused, and the reason names the rule.
    std::string reason;
    {
        LOCK(cs_main);
        CValidationState st;
        const bool ok = AcceptToMemoryPool(mempool, st, MakeTransactionRef(S), false, nullptr, nullptr, true, 0);
        if (!ok)
            reason = FormatStateMessage(st);
        BOOST_CHECK_MESSAGE(!ok,
            "a v6 witnessScript carrying HASH160 and CHECKSIG must be refused at relay; "
            "the spend with no preimage and no signature was accepted");
    }
    BOOST_CHECK_MESSAGE(reason.find(ScriptErrorString(SCRIPT_ERR_DISALLOWED_OPCODE)) != std::string::npos,
        "the relay refusal must name the opcode-set rule; got: " << reason);
    BOOST_CHECK_EQUAL(mempool.size(), 0u);

    // Block: refused by ConnectBlock. An empty block on the same tip still
    // connects, so the refusal is the script's.
    BOOST_CHECK_MESSAGE(!BlockIsValid(std::vector<CMutableTransaction>(1, S)),
        "a block spending the v6 HTLC with no preimage and no signature must fail ConnectBlock");
    BOOST_CHECK(BlockIsValid(std::vector<CMutableTransaction>()));
}

BOOST_AUTO_TEST_SUITE_END()
