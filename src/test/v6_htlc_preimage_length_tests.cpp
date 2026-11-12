// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// v6_htlc_preimage_length_tests.cpp: the HTLC template of a witness v6
// (P2WSH-Dilithium) witnessScript holds the preimage to 32 bytes.
//
// The claim branch of the template reads
//
//   OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY
//   <khPayee> OP_CHECKDILITHIUMKEYHASH OP_1
//
// OP_SIZE pushes the byte length of the top stack item as a script number and
// leaves the item in place, so the item measured is the item hashed. A hashlock
// alone is satisfied by a preimage of any length; with the check ahead of it the
// claim needs one of exactly 32 bytes.
//
// Two suites. The first drives the template through VerifyScript with ML-DSA-44
// keys and signatures on both sides of the length, with the same script less
// the check as the control, and pins what OP_SIZE pushes and the flag it runs
// under. The second funds the template in a mined regtest block and claims it
// with a preimage of 33 bytes, which the mempool and ConnectBlock must both
// refuse, and with one of 32 bytes, which both accept.

#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "key.h"
#include "primitives/transaction.h"
#include "pubkey.h"
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

valtype Sha256(const valtype& m)
{
    valtype h(32);
    CSHA256().Write(m.data(), m.size()).Finalize(h.data());
    return h;
}

CScript V6ProgramFor(const CScript& witnessScript)
{
    const valtype h = Sha256(valtype(witnessScript.begin(), witnessScript.end()));
    CScript spk;
    spk << OP_6 << h;
    return spk;
}

//! A party to the contract: an ML-DSA-44 key and the key hash the script
//! commits to.
struct Party {
    CKey key;
    valtype pub;      //!< the raw 1,312-byte key, as the witness carries it
    valtype keyhash;  //!< SHA256 of it, the script literal

    Party()
    {
        key.MakeNewKey(true);
        const CPubKey pk = key.GetPubKey();  // a local first: begin() and end() of one object
        pub.assign(pk.begin(), pk.end());
        keyhash = Sha256(pub);
    }

    //! SIGHASH_ALL over the witnessScript as scriptCode, input 0.
    valtype Sign(const CScript& ws, const CMutableTransaction& mtx, CAmount amount) const
    {
        const CTransaction tx(mtx);
        const uint256 sighash = SignatureHash(ws, tx, 0, SIGHASH_ALL, amount, SIGVERSION_WITNESS_V0, nullptr);
        valtype sig;
        BOOST_REQUIRE(key.Sign(sighash, sig));
        sig.push_back((unsigned char)SIGHASH_ALL);
        return sig;
    }
};

//! The height the refund branch waits for.
const int64_t REFUND_HEIGHT = 500;

//! The HTLC template: the claim on the IF branch, the refund on the ELSE
//! branch. With lengthCheck false it is the same script less
//! OP_SIZE 32 OP_EQUALVERIFY, the control.
CScript HtlcScript(const valtype& H, const Party& payee, const Party& payer, bool lengthCheck)
{
    CScript s;
    s << OP_IF;
    if (lengthCheck)
        s << OP_SIZE << CScriptNum(32) << OP_EQUALVERIFY;
    s << OP_SHA256 << H << OP_EQUALVERIFY << payee.keyhash << OP_CHECKDILITHIUMKEYHASH << OP_1
      << OP_ELSE
      << CScriptNum(REFUND_HEIGHT) << OP_CHECKLOCKTIMEVERIFY << OP_DROP
      << payer.keyhash << OP_CHECKDILITHIUMKEYHASH << OP_1
      << OP_ENDIF;
    return s;
}

//! The v6 witness of a signed branch:
//! [sig] [key] [items...] [witnessScript] [0x00-prefixed trailer].
CScriptWitness WitnessOf(const CScript& ws, const valtype& sig, const Party& signer, const std::vector<valtype>& items)
{
    CScriptWitness w;
    w.stack.push_back(sig);
    w.stack.push_back(signer.pub);
    for (const valtype& v : items)
        w.stack.push_back(v);
    w.stack.push_back(valtype(ws.begin(), ws.end()));
    w.stack.push_back(PrefixedPubkey(signer.pub));
    return w;
}

//! The claim's items above the signature and the key: the preimage, then the
//! true selector.
std::vector<valtype> ClaimItems(const valtype& preimage)
{
    std::vector<valtype> items;
    items.push_back(preimage);
    items.push_back(valtype(1, 0x01));
    return items;
}

const unsigned int P2WSH = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2WSH_DILITHIUM;

//! Every handler live: the three swap flags, the restored set and the
//! flag-gated covenant opcodes.
const unsigned int FULL = P2WSH | SCRIPT_VERIFY_DILITHIUM_KEYHASH | SCRIPT_VERIFY_V6_CONTROLFLOW |
                          SCRIPT_VERIFY_SCRIPT_RESTORE | SCRIPT_VERIFY_CTV | SCRIPT_VERIFY_CSFS |
                          SCRIPT_VERIFY_APO;

//! The value of the output the VerifyScript cases spend.
const CAmount AMOUNT = 10 * COIN;

//! A one-input version-2 spend with a sequence that leaves the lock time live.
CMutableTransaction SpendWith(uint32_t nLockTime)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = nLockTime;
    tx.vin.push_back(CTxIn(COutPoint(uint256S("01"), 0), CScript(), 0xfffffffe));
    tx.vout.push_back(CTxOut(AMOUNT - COIN, CScript() << OP_TRUE));
    return tx;
}

//! The verdict of VerifyScript on the v6 program of `ws` spent by `mtx` with
//! the witness `w`.
ScriptError VerdictOf(const CScript& ws, const CMutableTransaction& mtx, const CScriptWitness& w, unsigned int flags)
{
    const CTransaction tx(mtx);
    TransactionSignatureChecker checker(&tx, 0, AMOUNT);
    ScriptError serr = SCRIPT_ERR_OK;
    const bool ok = VerifyScript(CScript(), V6ProgramFor(ws), &w, flags, checker, &serr);
    if (ok != (serr == SCRIPT_ERR_OK))
        return SCRIPT_ERR_UNKNOWN_ERROR;
    return serr;
}

//! The claim branch, signed by `signer`, with `preimage`.
ScriptError ClaimVerdict(const CScript& ws, const Party& signer, const valtype& preimage)
{
    const CMutableTransaction mtx = SpendWith(0);
    return VerdictOf(ws, mtx, WitnessOf(ws, signer.Sign(ws, mtx, AMOUNT), signer, ClaimItems(preimage)), FULL);
}

//! The refund branch, signed by `signer`, in a transaction locked to nLockTime.
ScriptError RefundVerdict(const CScript& ws, const Party& signer, uint32_t nLockTime)
{
    const CMutableTransaction mtx = SpendWith(nLockTime);
    const std::vector<valtype> items(1, valtype());  // the false selector
    return VerdictOf(ws, mtx, WitnessOf(ws, signer.Sign(ws, mtx, AMOUNT), signer, items), FULL);
}

//! The verdict on a script with no key in it: witness [items...]
//! [witnessScript] [0x00-prefixed trailer].
ScriptError VerdictFor(const CScript& ws, unsigned int flags,
                       const std::vector<valtype>& items = std::vector<valtype>())
{
    CScriptWitness w;
    for (const valtype& v : items)
        w.stack.push_back(v);
    w.stack.push_back(valtype(ws.begin(), ws.end()));
    w.stack.push_back(valtype(1313, 0x00));
    return VerdictOf(ws, SpendWith(0), w, flags);
}

std::string Verdict(ScriptError e) { return std::string(ScriptErrorString(e)); }

} // namespace

BOOST_FIXTURE_TEST_SUITE(v6_htlc_preimage_length_tests, BasicTestingSetup)

// The hash commits to the preimage tried and the payee signs, so the claim
// meets the hashlock and the key check at every length. With the length check
// only 32 bytes claims; the same script less the check takes every length.
BOOST_AUTO_TEST_CASE(the_template_refuses_a_preimage_that_is_not_32_bytes)
{
    const Party payee, payer;
    // 520 is the largest element a script push carries, 2,421 the length of a
    // signature item with its hash type.
    const size_t lengths[] = {0, 1, 31, 33, 127, 128, 520, 521, 2421};
    for (size_t len : lengths) {
        const valtype preimage(len, 0x07);
        const valtype H = Sha256(preimage);
        const ScriptError checked = ClaimVerdict(HtlcScript(H, payee, payer, true), payee, preimage);
        BOOST_CHECK_MESSAGE(checked == SCRIPT_ERR_EQUALVERIFY,
            "a " << len << "-byte preimage must stop at the length check; got " << Verdict(checked));
        const ScriptError unchecked = ClaimVerdict(HtlcScript(H, payee, payer, false), payee, preimage);
        BOOST_CHECK_MESSAGE(unchecked == SCRIPT_ERR_OK,
            "the script less the length check takes a " << len << "-byte preimage; got " << Verdict(unchecked));
    }

    const valtype preimage(32, 0x07);
    const valtype H = Sha256(preimage);
    const ScriptError checked = ClaimVerdict(HtlcScript(H, payee, payer, true), payee, preimage);
    BOOST_CHECK_MESSAGE(checked == SCRIPT_ERR_OK, "a 32-byte preimage must claim; got " << Verdict(checked));
    BOOST_CHECK_EQUAL(ClaimVerdict(HtlcScript(H, payee, payer, false), payee, preimage), SCRIPT_ERR_OK);
}

// The rules the template had before the length check are as they were: the
// hashlock, the key of each branch and the refund's lock.
BOOST_AUTO_TEST_CASE(the_hashlock_the_keys_and_the_refund_are_unchanged)
{
    const Party payee, payer;
    const valtype preimage(32, 0x07);
    const CScript ws = HtlcScript(Sha256(preimage), payee, payer, true);

    ScriptError v = ClaimVerdict(ws, payee, preimage);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_OK, "the payee must claim with the 32-byte preimage; got " << Verdict(v));

    // 32 bytes of another value pass the length and stop at the hashlock.
    v = ClaimVerdict(ws, payee, valtype(32, 0x08));
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_EQUALVERIFY, "a wrong 32-byte preimage must stop at the hashlock; got " << Verdict(v));

    // The payer's key does not open the claim branch, nor the payee's the refund.
    v = ClaimVerdict(ws, payer, preimage);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_CHECKDILITHIUMKEYHASH, "the payer's key must not claim; got " << Verdict(v));
    v = RefundVerdict(ws, payee, REFUND_HEIGHT);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_CHECKDILITHIUMKEYHASH, "the payee's key must not refund; got " << Verdict(v));

    // The refund at its height, and one block short of it.
    v = RefundVerdict(ws, payer, REFUND_HEIGHT);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_OK, "the payer must refund at the lock height; got " << Verdict(v));
    v = RefundVerdict(ws, payer, REFUND_HEIGHT - 1);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_UNSATISFIED_LOCKTIME, "the refund one block short must wait; got " << Verdict(v));

    // A claim with nothing under the selector: the length check has no item to read.
    v = VerdictFor(ws, FULL, std::vector<valtype>(1, valtype(1, 0x01)));
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_INVALID_STACK_OPERATION,
        "a claim with no item under the selector must stop at OP_SIZE; got " << Verdict(v));
}

// OP_SIZE pushes the length of the top item as a script number and leaves the
// item: OP_SIZE <n> OP_EQUALVERIFY consumes the pushed length, and the item
// still hashes to its own digest afterwards, alone on the stack.
BOOST_AUTO_TEST_CASE(op_size_pushes_the_length_and_leaves_the_item)
{
    struct Row { size_t len; valtype number; };
    const Row rows[] = {
        {0, {}},
        {1, {0x01}},
        {16, {0x10}},
        {32, {0x20}},
        {127, {0x7f}},
        {128, {0x80, 0x00}},  // a second byte keeps the number positive
        {255, {0xff, 0x00}},
        {256, {0x00, 0x01}},
        {520, {0x08, 0x02}},
        {521, {0x09, 0x02}},
        {2421, {0x75, 0x09}},
    };
    for (const Row& row : rows) {
        const valtype item(row.len, 0x5a);
        const CScript s = CScript() << OP_SIZE << row.number << OP_EQUALVERIFY << OP_SHA256 << Sha256(item) << OP_EQUAL;
        const ScriptError v = VerdictFor(s, FULL, std::vector<valtype>(1, item));
        BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_OK,
            "OP_SIZE on a " << row.len << "-byte item must push its length and leave the item; got " << Verdict(v));
    }

    // Another number does not match: 33 against a 32-byte item.
    {
        const valtype item(32, 0x5a);
        const CScript s = CScript() << OP_SIZE << CScriptNum(33) << OP_EQUALVERIFY << OP_SHA256 << Sha256(item) << OP_EQUAL;
        const ScriptError v = VerdictFor(s, FULL, std::vector<valtype>(1, item));
        BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_EQUALVERIFY, "the length of a 32-byte item is not 33; got " << Verdict(v));
    }

    // The item read is the top one, and each stays where it was: seven bytes
    // above five.
    {
        std::vector<valtype> items;
        items.push_back(valtype(5, 0x5a));
        items.push_back(valtype(7, 0x5a));
        const CScript s = CScript() << OP_SIZE << CScriptNum(7) << OP_EQUALVERIFY << OP_DROP
                                    << OP_SIZE << CScriptNum(5) << OP_EQUALVERIFY << OP_DROP << OP_1;
        const ScriptError v = VerdictFor(s, FULL, items);
        BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_OK, "OP_SIZE must read the top item; got " << Verdict(v));
    }

    // With no item to read it fails; in a branch not taken it does not run.
    ScriptError v = VerdictFor(CScript() << OP_SIZE, FULL);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_INVALID_STACK_OPERATION, "OP_SIZE on an empty stack; got " << Verdict(v));
    v = VerdictFor(CScript() << OP_1 << OP_IF << OP_SIZE << OP_ENDIF << OP_1, FULL);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_INVALID_STACK_OPERATION, "OP_SIZE in the branch taken; got " << Verdict(v));
    v = VerdictFor(CScript() << OP_0 << OP_IF << OP_SIZE << OP_ENDIF << OP_1, FULL);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_OK, "OP_SIZE in a branch not taken; got " << Verdict(v));
}

// The handler runs when SCRIPT_VERIFY_V6_CONTROLFLOW is set and only then.
// OP_SIZE OP_CAT over one one-byte item: with the handler OP_CAT joins the item
// and its length into a single item; without it OP_CAT finds one item. OP_CAT
// has no flag of its own. With the v6 flag clear nothing is checked.
BOOST_AUTO_TEST_CASE(op_size_runs_under_the_control_flow_flag)
{
    const CScript s = CScript() << OP_SIZE << OP_CAT;
    const std::vector<valtype> item(1, valtype(1, 0x01));

    ScriptError v = VerdictFor(s, FULL, item);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_OK, "every flag set; got " << Verdict(v));
    v = VerdictFor(s, P2WSH | SCRIPT_VERIFY_V6_CONTROLFLOW, item);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_OK, "the v6 and control-flow flags alone; got " << Verdict(v));

    v = VerdictFor(s, FULL & ~SCRIPT_VERIFY_V6_CONTROLFLOW, item);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_INVALID_STACK_OPERATION, "every flag but control flow; got " << Verdict(v));
    v = VerdictFor(s, P2WSH, item);
    BOOST_CHECK_MESSAGE(v == SCRIPT_ERR_INVALID_STACK_OPERATION, "the v6 flag alone; got " << Verdict(v));

    BOOST_CHECK_EQUAL(VerdictFor(s, SCRIPT_VERIFY_WITNESS, item), SCRIPT_ERR_OK);
}

// The check is the four bytes 82 01 20 88 between OP_IF and OP_SHA256, and
// nothing else in the template moves.
BOOST_AUTO_TEST_CASE(the_length_check_is_four_bytes_ahead_of_the_hashlock)
{
    const Party payee, payer;
    const valtype H(32, 0xab);
    const CScript with = HtlcScript(H, payee, payer, true);
    const CScript without = HtlcScript(H, payee, payer, false);

    const unsigned char check[] = {OP_SIZE, 0x01, 0x20, OP_EQUALVERIFY};
    valtype expected(without.begin(), without.begin() + 1);
    expected.insert(expected.end(), check, check + sizeof(check));
    expected.insert(expected.end(), without.begin() + 1, without.end());

    BOOST_CHECK(valtype(with.begin(), with.end()) == expected);
    BOOST_CHECK_EQUAL(with.size(), without.size() + 4);
    BOOST_CHECK_EQUAL(with[0], (unsigned char)OP_IF);
    BOOST_CHECK_EQUAL(with[5], (unsigned char)OP_SHA256);
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// The chain path: the template funded in a mined block, claimed with a
// preimage of 33 bytes and with one of 32.
// ---------------------------------------------------------------------------
BOOST_FIXTURE_TEST_SUITE(v6_htlc_preimage_length_chain_tests, DilithiumChainSetup)

BOOST_AUTO_TEST_CASE(a_33_byte_preimage_is_refused_at_relay_and_in_a_block)
{
    const Party payee, payer;
    const valtype secret33(33, 0x07);
    const valtype secret32(32, 0x07);

    // Three contracts between the same two keys: the length check with the
    // hash of the 33-byte secret, the length check with the hash of the 32-byte
    // secret, and no length check with the hash of the 33-byte secret.
    const CScript wsLong = HtlcScript(Sha256(secret33), payee, payer, true);
    const CScript wsExact = HtlcScript(Sha256(secret32), payee, payer, true);
    const CScript wsControl = HtlcScript(Sha256(secret33), payee, payer, false);

    // F: coinbase[0] to the three v6 outputs, mined.
    const CAmount cbValue = coinbaseTxns[0].vout[0].nValue;
    const CAmount FEE = COIN;
    BOOST_REQUIRE(cbValue > 8 * FEE);
    const CAmount each = (cbValue - FEE) / 3;
    CMutableTransaction F;
    F.nVersion = 2;
    F.vin.push_back(CTxIn(COutPoint(coinbaseTxns[0].GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
    F.vout.push_back(CTxOut(each, V6ProgramFor(wsLong)));
    F.vout.push_back(CTxOut(each, V6ProgramFor(wsExact)));
    F.vout.push_back(CTxOut(each, V6ProgramFor(wsControl)));
    SignInput(F, 0, coinbaseSpk, cbValue);
    const CBlock bF = CreateAndProcessBlock(std::vector<CMutableTransaction>(1, F), coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == bF.GetHash(), "the funding block must connect");

    // S: the payee claims output n of F with `secret`, to the coinbase key.
    // Witness: [sig] [key] [secret] [true selector] [witnessScript] [trailer].
    auto claim = [&](unsigned int n, const CScript& ws, const valtype& secret) {
        CMutableTransaction S;
        S.nVersion = 2;
        S.vin.push_back(CTxIn(COutPoint(F.GetHash(), n), CScript(), CTxIn::SEQUENCE_FINAL));
        S.vout.push_back(CTxOut(each - FEE, coinbaseSpk));
        S.vin[0].scriptWitness = WitnessOf(ws, payee.Sign(ws, S, each), payee, ClaimItems(secret));
        return S;
    };
    // The relay verdict: the reject reason, or "" when accepted. The mempool is
    // emptied after each try, so every claim is judged on its own.
    auto relay = [&](const CMutableTransaction& S) -> std::string {
        LOCK(cs_main);
        CValidationState st;
        const bool ok = AcceptToMemoryPool(mempool, st, MakeTransactionRef(S), false, nullptr, nullptr, true, 0);
        const std::string reason = ok ? std::string() : FormatStateMessage(st);
        mempool.clear();
        return reason;
    };
    auto one = [](const CMutableTransaction& S) { return std::vector<CMutableTransaction>(1, S); };
    auto unspent = [&](unsigned int n) {
        LOCK(cs_main);
        const CCoins* coins = pcoinsTip->AccessCoins(F.GetHash());
        return coins != nullptr && coins->IsAvailable(n);
    };

    // The 33-byte claim of the contract with the length check: refused at
    // relay, the failed operation named, and refused in a block.
    const CMutableTransaction SLong = claim(0, wsLong, secret33);
    std::string r = relay(SLong);
    BOOST_CHECK_MESSAGE(r.find(ScriptErrorString(SCRIPT_ERR_EQUALVERIFY)) != std::string::npos,
        "the 33-byte claim must be refused at relay by the length check; got: "
        << (r.empty() ? std::string("accepted") : r));
    BOOST_CHECK_MESSAGE(!BlockIsValid(one(SLong)), "a block holding the 33-byte claim must fail ConnectBlock");

    // The same claim of the contract less the check: accepted at relay and
    // valid in a block. The hash and the signature hold there, so the refusal
    // above is the length check's.
    const CMutableTransaction SControl = claim(2, wsControl, secret33);
    r = relay(SControl);
    BOOST_CHECK_MESSAGE(r.empty(), "without the length check the 33-byte claim is accepted at relay; got: " << r);
    BOOST_CHECK_MESSAGE(BlockIsValid(one(SControl)), "without the length check a block holding the 33-byte claim connects");

    // The 32-byte claim of the contract with the length check: accepted at
    // relay and valid in a block.
    const CMutableTransaction SExact = claim(1, wsExact, secret32);
    r = relay(SExact);
    BOOST_CHECK_MESSAGE(r.empty(), "the 32-byte claim must be accepted at relay; got: " << r);
    BOOST_CHECK_MESSAGE(BlockIsValid(one(SExact)), "a block holding the 32-byte claim must connect");

    // An empty block on the same tip connects: the refusal is the claim's.
    BOOST_CHECK(BlockIsValid(std::vector<CMutableTransaction>()));

    // Mined, the control first: each claim spends its output, and the output
    // behind the 33-byte secret and the length check stays unspent.
    const CBlock bControl = CreateAndProcessBlock(one(SControl), coinbaseSpk);
    BOOST_CHECK_MESSAGE(chainActive.Tip()->GetBlockHash() == bControl.GetHash(), "the block with the control claim must connect");
    BOOST_CHECK(!unspent(2));
    const CBlock bExact = CreateAndProcessBlock(one(SExact), coinbaseSpk);
    BOOST_CHECK_MESSAGE(chainActive.Tip()->GetBlockHash() == bExact.GetHash(), "the block with the 32-byte claim must connect");
    BOOST_CHECK(!unspent(1));
    BOOST_CHECK(unspent(0));

    // On the new tip the 33-byte claim is refused as before.
    r = relay(SLong);
    BOOST_CHECK_MESSAGE(r.find(ScriptErrorString(SCRIPT_ERR_EQUALVERIFY)) != std::string::npos,
        "the 33-byte claim stays refused at relay; got: " << (r.empty() ? std::string("accepted") : r));
    BOOST_CHECK_MESSAGE(!BlockIsValid(one(SLong)), "a block holding the 33-byte claim stays invalid");
}

BOOST_AUTO_TEST_SUITE_END()
