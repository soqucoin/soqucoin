// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// witness_v6_narrowing_tests.cpp: what a witness version 6 script refuses.
//
// Witness version 6 carries the swap's script: the key-hash check, the
// conditionals, the hashlock and the two timelocks. Four forms are outside it:
//
//   * OP_CHECKSIGFROMSTACK (0xb4) and OP_CHECKTEMPLATEVERIFY (0xb3), which
//     belong to witness version 11. The pre-scan refuses either byte before
//     execution, in a branch not taken too.
//   * A signature whose hash type is an anyprevout type (the low seven bits
//     0x41 or 0x42). The key-hash check refuses it before a message is
//     computed.
//   * The OP_MUL product INT64_MIN, which needs nine bytes as a script number.
//
// Each refusal holds in every flag state in which the version 6 branch runs,
// so it holds on every tier of every network, and the verdict of a version 6
// spend does not depend on the ctv, apo and csfs deployments.
//
// Two suites. The first drives VerifyScript with stated flags. The second
// spends a version 6 output on a regtest chain through the mempool and through
// a block.

#include "amount.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "hash.h"
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

#include <limits>
#include <string>
#include <vector>

namespace {

typedef std::vector<unsigned char> valtype;

const unsigned int V6_RUNS = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2WSH_DILITHIUM;

//! The flags a block sets beside the version 6 gate. Every subset of them is a
//! state in which the version 6 branch runs.
const unsigned int OTHER_FLAGS[] = {
    SCRIPT_VERIFY_DILITHIUM_KEYHASH, SCRIPT_VERIFY_V6_CONTROLFLOW, SCRIPT_VERIFY_SCRIPT_RESTORE,
    SCRIPT_VERIFY_CTV, SCRIPT_VERIFY_APO, SCRIPT_VERIFY_CSFS,
};
const unsigned int N_OTHER = sizeof(OTHER_FLAGS) / sizeof(OTHER_FLAGS[0]);

//! The state of a test network's block, and of a mainnet block from the height
//! of version 6, without the three deployments of witness version 11.
const unsigned int SWAP_FLAGS = V6_RUNS | SCRIPT_VERIFY_DILITHIUM_KEYHASH | SCRIPT_VERIFY_V6_CONTROLFLOW |
                                SCRIPT_VERIFY_SCRIPT_RESTORE;

unsigned int Subset(unsigned int mask)
{
    unsigned int flags = 0;
    for (unsigned int i = 0; i < N_OTHER; ++i)
        if (mask & (1U << i))
            flags |= OTHER_FLAGS[i];
    return flags;
}

unsigned int Covenant(unsigned int mask)
{
    return ((mask & 1) ? SCRIPT_VERIFY_CTV : 0) | ((mask & 2) ? SCRIPT_VERIFY_APO : 0) |
           ((mask & 4) ? SCRIPT_VERIFY_CSFS : 0);
}

std::string Name(ScriptError e) { return std::string(ScriptErrorString(e)); }

CScript V6ProgramFor(const CScript& witnessScript)
{
    uint256 h;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(h.begin());
    CScript spk;
    spk << OP_6 << valtype(h.begin(), h.end());
    return spk;
}

valtype KeyBytes(const CKey& key)
{
    const CPubKey pk = key.GetPubKey();
    return valtype(pk.begin(), pk.end());
}

valtype KeyHash(const valtype& rawKey)
{
    valtype h(32);
    CSHA256().Write(rawKey.data(), rawKey.size()).Finalize(h.data());
    return h;
}

//! A version 6 output and the transaction that spends it.
struct Spend {
    CScript ws;
    CAmount amount;
    CMutableTransaction tx;
    std::vector<valtype> items;

    Spend() : amount(50 * COIN)
    {
        tx.nVersion = 2;
        tx.nLockTime = 0;
        CTxIn in;
        in.prevout.hash = uint256S("0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
        in.prevout.n = 0;
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);
        tx.vout.push_back(CTxOut(49 * COIN, CScript() << OP_TRUE));
    }

    //! A signature of the key-hash check: over the message of the version 6
    //! signature version for this hash type, with the hash type byte appended.
    valtype Sign(const CKey& key, int hashType) const
    {
        const CTransaction ctx(tx);
        const uint256 sighash = SignatureHash(ws, ctx, 0, hashType, amount, SIGVERSION_WITNESS_V0, nullptr);
        valtype sig;
        BOOST_REQUIRE(key.Sign(sighash, sig));
        BOOST_REQUIRE_EQUAL(sig.size(), 2420u);
        sig.push_back(static_cast<unsigned char>(hashType));
        return sig;
    }

    ScriptError Verdict(unsigned int flags) const
    {
        CScriptWitness w;
        for (const valtype& v : items)
            w.stack.push_back(v);
        w.stack.push_back(valtype(ws.begin(), ws.end()));
        w.stack.push_back(valtype(1313, 0x00));
        const CTransaction ctx(tx);
        const TransactionSignatureChecker checker(&ctx, 0, amount);
        ScriptError serr = SCRIPT_ERR_OK;
        VerifyScript(CScript(), V6ProgramFor(ws), &w, flags, checker, &serr);
        return serr;
    }
};

//! The template hash OP_CHECKTEMPLATEVERIFY compares for input 0.
struct TemplateReader : public TransactionSignatureChecker {
    TemplateReader(const CTransaction* tx, const CAmount& amount) : TransactionSignatureChecker(tx, 0, amount) {}
    valtype Template() const
    {
        valtype h(32);
        ComputeTemplateHash(h.data());
        return h;
    }
};

valtype TemplateOf(const CMutableTransaction& tx, const CAmount& amount)
{
    const CTransaction ctx(tx);
    return TemplateReader(&ctx, amount).Template();
}

//! OP_CHECKSIGFROMSTACK with a signature that verifies: the items are the
//! signature, the message and the key.
Spend SignedChecksigfromstack(const CKey& key)
{
    Spend s;
    s.ws = CScript() << OP_CHECKSIGFROMSTACK << OP_1;
    const valtype msg(40, 0x6d);
    valtype sig;
    BOOST_REQUIRE(key.Sign(Hash(msg.begin(), msg.end()), sig));
    s.items.push_back(sig);
    s.items.push_back(msg);
    s.items.push_back(KeyBytes(key));
    return s;
}

//! OP_CHECKTEMPLATEVERIFY over the template of the spending transaction.
Spend MatchingTemplate()
{
    Spend s;
    s.ws = CScript() << TemplateOf(s.tx, s.amount) << OP_CHECKTEMPLATEVERIFY;
    return s;
}

//! Two key-hash checks and OP_1, both signatures of one hash type.
Spend TwoOfTwo(const CKey& a, const CKey& b, int hashType)
{
    Spend s;
    const valtype ka = KeyBytes(a), kb = KeyBytes(b);
    s.ws = CScript() << KeyHash(kb) << OP_CHECKDILITHIUMKEYHASH << KeyHash(ka) << OP_CHECKDILITHIUMKEYHASH << OP_1;
    s.items.push_back(s.Sign(a, hashType));
    s.items.push_back(ka);
    s.items.push_back(s.Sign(b, hashType));
    s.items.push_back(kb);
    return s;
}

const uint32_t REFUND_LOCKTIME = 500;

CScript SwapScript(const valtype& hash, const valtype& claimKey, const valtype& refundKey)
{
    return CScript() << OP_IF
                       << OP_SIZE << CScriptNum(32) << OP_EQUALVERIFY
                       << OP_SHA256 << hash << OP_EQUALVERIFY
                       << KeyHash(claimKey) << OP_CHECKDILITHIUMKEYHASH << OP_1
                     << OP_ELSE
                       << CScriptNum(REFUND_LOCKTIME) << OP_CHECKLOCKTIMEVERIFY << OP_DROP
                       << KeyHash(refundKey) << OP_CHECKDILITHIUMKEYHASH << OP_1
                     << OP_ENDIF;
}

//! The swap's claim: the signature, the key, the preimage and a true selector.
Spend SwapClaim(const CKey& claim, const CKey& refund)
{
    Spend s;
    const valtype preimage(32, 0x07);
    valtype hash(32);
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash.data());
    s.ws = SwapScript(hash, KeyBytes(claim), KeyBytes(refund));
    s.items.push_back(s.Sign(claim, SIGHASH_ALL));
    s.items.push_back(KeyBytes(claim));
    s.items.push_back(preimage);
    s.items.push_back(valtype(1, 0x01));
    return s;
}

//! The swap's refund: the signature, the key and an empty selector, in a
//! transaction whose lock time has reached the script's.
Spend SwapRefund(const CKey& claim, const CKey& refund)
{
    Spend s;
    s.tx.nLockTime = REFUND_LOCKTIME;
    s.tx.vin[0].nSequence = 0xfffffffe;
    s.ws = SwapScript(valtype(32, 0xab), KeyBytes(claim), KeyBytes(refund));
    s.items.push_back(s.Sign(refund, SIGHASH_ALL));
    s.items.push_back(KeyBytes(refund));
    s.items.push_back(valtype());
    return s;
}

//! The four hash type bytes whose low seven bits name an anyprevout type.
const int ANYPREVOUT_BYTES[] = {0x41, 0x42, 0xc1, 0xc2};

//! Every pair of eight-byte operands whose product is INT64_MIN: a power of
//! two and its negated complement, in both orders.
std::vector<std::pair<int64_t, int64_t> > OperandsOfTheLowestProduct()
{
    std::vector<std::pair<int64_t, int64_t> > out;
    for (int k = 1; k <= 62; ++k) {
        const int64_t p = int64_t(1) << k;
        const int64_t q = int64_t(1) << (63 - k);
        out.push_back(std::make_pair(-p, q));
        out.push_back(std::make_pair(p, -q));
    }
    return out;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(witness_v6_narrowing_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_v6_script_with_checksigfromstack_is_refused_in_every_flag_state)
{
    CKey key;
    key.MakeNewKey(true);

    std::vector<Spend> spends;
    {
        // The byte with one item under it.
        Spend s;
        s.ws = CScript() << OP_1 << OP_CHECKSIGFROMSTACK;
        spends.push_back(s);
    }
    spends.push_back(SignedChecksigfromstack(key));
    {
        // The byte in a branch not taken.
        Spend s;
        s.ws = CScript() << OP_0 << OP_IF << OP_CHECKSIGFROMSTACK << OP_ENDIF << OP_1;
        spends.push_back(s);
    }

    for (size_t i = 0; i < spends.size(); ++i) {
        for (unsigned int mask = 0; mask < (1U << N_OTHER); ++mask) {
            const unsigned int flags = V6_RUNS | Subset(mask);
            const ScriptError got = spends[i].Verdict(flags);
            BOOST_CHECK_MESSAGE(got == SCRIPT_ERR_DISALLOWED_OPCODE,
                "spend " << i << ", flags " << flags << ": got " << Name(got));
        }
        // Where version 6 does not run the output is spent by anyone.
        BOOST_CHECK_EQUAL(spends[i].Verdict(SCRIPT_VERIFY_WITNESS), SCRIPT_ERR_OK);
    }
}

BOOST_AUTO_TEST_CASE(a_v6_script_with_checktemplateverify_is_refused_in_every_flag_state)
{
    std::vector<Spend> spends;
    {
        // The byte over a hash that is not the transaction's template.
        Spend s;
        s.ws = CScript() << valtype(32, 0x07) << OP_CHECKTEMPLATEVERIFY;
        spends.push_back(s);
    }
    spends.push_back(MatchingTemplate());
    {
        // The byte in a branch not taken.
        Spend s;
        s.ws = CScript() << OP_0 << OP_IF << valtype(32, 0x07) << OP_CHECKTEMPLATEVERIFY << OP_ENDIF << OP_1;
        spends.push_back(s);
    }

    for (size_t i = 0; i < spends.size(); ++i) {
        for (unsigned int mask = 0; mask < (1U << N_OTHER); ++mask) {
            const unsigned int flags = V6_RUNS | Subset(mask);
            const ScriptError got = spends[i].Verdict(flags);
            BOOST_CHECK_MESSAGE(got == SCRIPT_ERR_DISALLOWED_OPCODE,
                "spend " << i << ", flags " << flags << ": got " << Name(got));
        }
        BOOST_CHECK_EQUAL(spends[i].Verdict(SCRIPT_VERIFY_WITNESS), SCRIPT_ERR_OK);
    }
}

// Either byte inside a push is data.
BOOST_AUTO_TEST_CASE(the_two_bytes_inside_a_push_are_data)
{
    Spend s;
    valtype data;
    data.push_back(OP_CHECKTEMPLATEVERIFY);
    data.push_back(OP_CHECKSIGFROMSTACK);
    s.ws = CScript() << data;
    for (unsigned int mask = 0; mask < (1U << N_OTHER); ++mask)
        BOOST_CHECK_EQUAL(s.Verdict(V6_RUNS | Subset(mask)), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(a_v6_keyhash_spend_with_an_anyprevout_signature_is_refused_in_every_flag_state)
{
    CKey a, b;
    a.MakeNewKey(true);
    b.MakeNewKey(true);

    const Spend ordinary = TwoOfTwo(a, b, SIGHASH_ALL);
    std::vector<Spend> anyprevout;
    for (int byte : ANYPREVOUT_BYTES)
        anyprevout.push_back(TwoOfTwo(a, b, byte));

    // Every state in which the key-hash check runs: the version 6 gate, the
    // key-hash flag, and each subset of the other five.
    for (unsigned int mask = 0; mask < (1U << N_OTHER); ++mask) {
        const unsigned int flags = V6_RUNS | SCRIPT_VERIFY_DILITHIUM_KEYHASH | Subset(mask);
        for (size_t i = 0; i < anyprevout.size(); ++i) {
            const ScriptError got = anyprevout[i].Verdict(flags);
            BOOST_CHECK_MESSAGE(got == SCRIPT_ERR_SIG_HASHTYPE,
                "hash type 0x" << std::hex << ANYPREVOUT_BYTES[i] << std::dec << ", flags " << flags
                               << ": got " << Name(got));
        }
        BOOST_CHECK_MESSAGE(ordinary.Verdict(flags) == SCRIPT_ERR_OK,
            "the same output signed with SIGHASH_ALL, flags " << flags << ": got " << Name(ordinary.Verdict(flags)));
    }

    // One anyprevout signature beside an ordinary one is refused as well,
    // whichever check meets it.
    for (int first = 0; first < 2; ++first) {
        Spend s = TwoOfTwo(a, b, SIGHASH_ALL);
        s.items[first ? 0 : 2] = s.Sign(first ? a : b, SIGHASH_ANYPREVOUTANYSCRIPT);
        BOOST_CHECK_EQUAL(s.Verdict(SWAP_FLAGS | SCRIPT_VERIFY_APO), SCRIPT_ERR_SIG_HASHTYPE);
    }
}

BOOST_AUTO_TEST_CASE(the_v6_verdict_does_not_read_the_three_flags)
{
    CKey a, b;
    a.MakeNewKey(true);
    b.MakeNewKey(true);

    struct Row {
        const char* name;
        Spend spend;
        ScriptError expected;
    };
    std::vector<Row> corpus;
    corpus.push_back({"the swap's claim", SwapClaim(a, b), SCRIPT_ERR_OK});
    corpus.push_back({"the swap's refund", SwapRefund(a, b), SCRIPT_ERR_OK});
    corpus.push_back({"two key-hash checks signed SIGHASH_ALL", TwoOfTwo(a, b, SIGHASH_ALL), SCRIPT_ERR_OK});
    corpus.push_back({"OP_CHECKSIGFROMSTACK with a signature that verifies", SignedChecksigfromstack(a),
                      SCRIPT_ERR_DISALLOWED_OPCODE});
    corpus.push_back({"OP_CHECKTEMPLATEVERIFY over the transaction's template", MatchingTemplate(),
                      SCRIPT_ERR_DISALLOWED_OPCODE});
    for (int byte : ANYPREVOUT_BYTES)
        corpus.push_back({"two key-hash checks signed with an anyprevout type", TwoOfTwo(a, b, byte),
                          SCRIPT_ERR_SIG_HASHTYPE});

    for (const Row& row : corpus) {
        for (unsigned int mask = 0; mask < 8; ++mask) {
            const ScriptError got = row.spend.Verdict(SWAP_FLAGS | Covenant(mask));
            BOOST_CHECK_MESSAGE(got == row.expected,
                row.name << ", ctv/apo/csfs mask " << mask << ": got " << Name(got) << ", expected "
                         << Name(row.expected));
        }
    }
}

BOOST_AUTO_TEST_CASE(the_product_int64_min_is_refused_in_a_v6_script)
{
    const std::vector<std::pair<int64_t, int64_t> > operands = OperandsOfTheLowestProduct();
    BOOST_REQUIRE_EQUAL(operands.size(), 124u);

    for (const std::pair<int64_t, int64_t>& ab : operands) {
        // The product is INT64_MIN: the quotient is exact and the remainder is
        // zero, checked without multiplying.
        BOOST_REQUIRE_EQUAL(std::numeric_limits<int64_t>::min() / ab.first, ab.second);
        BOOST_REQUIRE_EQUAL(std::numeric_limits<int64_t>::min() % ab.first, 0);

        Spend s;
        s.ws = CScript() << CScriptNum(ab.first) << CScriptNum(ab.second) << OP_MUL;
        for (unsigned int mask = 0; mask < 8; ++mask) {
            const ScriptError got = s.Verdict(SWAP_FLAGS | Covenant(mask));
            BOOST_CHECK_MESSAGE(got == SCRIPT_ERR_PUSH_SIZE,
                ab.first << " times " << ab.second << ", ctv/apo/csfs mask " << mask << ": got " << Name(got));
        }

        // The interpreter itself, under the version 6 signature version.
        std::vector<valtype> stack;
        ScriptError serr = SCRIPT_ERR_OK;
        const bool ok = EvalScript(stack, s.ws, SWAP_FLAGS, BaseSignatureChecker(), SIGVERSION_WITNESS_V0, &serr);
        BOOST_CHECK_MESSAGE(!ok && serr == SCRIPT_ERR_PUSH_SIZE,
            ab.first << " times " << ab.second << " through EvalScript: " << (ok ? "accepted" : Name(serr)));
    }
}

// The products next to it are eight-byte numbers and are pushed as before.
BOOST_AUTO_TEST_CASE(the_neighbours_of_the_product_are_pushed_as_eight_bytes)
{
    const int64_t a = 153092023;      // 7 * 7 * 73 * 127 * 337
    const int64_t b = 60247241209LL;  // 92737 * 649657
    BOOST_REQUIRE_EQUAL(std::numeric_limits<int64_t>::max() / a, b);
    BOOST_REQUIRE_EQUAL(std::numeric_limits<int64_t>::max() % a, 0);

    const std::pair<int64_t, int64_t> neighbours[] = {
        std::make_pair(a, b),                                    // INT64_MAX
        std::make_pair(-a, b),                                   // INT64_MIN + 1
        std::make_pair(a, -b),                                   // INT64_MIN + 1
        std::make_pair(-int64_t(4294967296LL), int64_t(2147483647)),  // INT64_MIN + 4294967296
        std::make_pair(int64_t(4294967296LL), int64_t(2147483647)),   // INT64_MAX - 4294967295
    };
    for (const std::pair<int64_t, int64_t>& ab : neighbours) {
        Spend s;
        s.ws = CScript() << CScriptNum(ab.first) << CScriptNum(ab.second) << OP_MUL
                         << OP_SIZE << CScriptNum(8) << OP_EQUALVERIFY;
        for (unsigned int mask = 0; mask < 8; ++mask) {
            const ScriptError got = s.Verdict(SWAP_FLAGS | Covenant(mask));
            BOOST_CHECK_MESSAGE(got == SCRIPT_ERR_OK,
                ab.first << " times " << ab.second << ", ctv/apo/csfs mask " << mask << ": got " << Name(got));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// The chain path: a version 6 output on a regtest chain, spent through each
// refused form. The mempool refuses the spend with the reason of a spend that
// is invalid in a block, and a block that holds it does not connect.
// ---------------------------------------------------------------------------
BOOST_FIXTURE_TEST_SUITE(witness_v6_narrowing_chain_tests, DilithiumChainSetup)

namespace {

const CAmount SEEDED = 10 * COIN;
const CAmount FEE = COIN;

std::string MandatoryRefusal(ScriptError e)
{
    return std::string("mandatory-script-verify-flag-failed (") + ScriptErrorString(e) + ")";
}

CMutableTransaction SpendOf(const COutPoint& out, const CScript& payTo)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.push_back(CTxIn(out, CScript(), CTxIn::SEQUENCE_FINAL));
    tx.vout.push_back(CTxOut(SEEDED - FEE, payTo));
    return tx;
}

void SetWitness(CMutableTransaction& tx, const std::vector<valtype>& items, const CScript& ws, const valtype& trailer)
{
    CScriptWitness w;
    for (const valtype& v : items)
        w.stack.push_back(v);
    w.stack.push_back(valtype(ws.begin(), ws.end()));
    w.stack.push_back(trailer);
    tx.vin[0].scriptWitness = w;
}

//! The mempool's answer: an empty string when the transaction is accepted,
//! the reject reason when it is not.
std::string RelayRefusal(const CMutableTransaction& tx)
{
    LOCK(cs_main);
    CValidationState st;
    if (AcceptToMemoryPool(mempool, st, MakeTransactionRef(tx), false, nullptr, nullptr, true, 0))
        return std::string();
    return st.GetRejectReason();
}

} // namespace

BOOST_AUTO_TEST_CASE(each_refused_form_fails_at_relay_and_in_a_block)
{
    const valtype key = coinbasePkBytes;
    const valtype trailer = PrefixedPubkey(coinbasePkBytes);

    // OP_CHECKSIGFROMSTACK with a signature that verifies.
    {
        const CScript ws = CScript() << OP_CHECKSIGFROMSTACK << OP_1;
        CMutableTransaction tx = SpendOf(SeedCoin(V6ProgramFor(ws), SEEDED, 0xa1), coinbaseSpk);
        const valtype msg(40, 0x6d);
        valtype sig;
        BOOST_REQUIRE(coinbaseKey.Sign(Hash(msg.begin(), msg.end()), sig));
        SetWitness(tx, {sig, msg, key}, ws, trailer);
        BOOST_CHECK_EQUAL(RelayRefusal(tx), MandatoryRefusal(SCRIPT_ERR_DISALLOWED_OPCODE));
        BOOST_CHECK(!BlockIsValid(std::vector<CMutableTransaction>(1, tx)));
    }

    // OP_CHECKTEMPLATEVERIFY over the template of the spending transaction.
    // The template does not cover the outpoint, so it is computed first.
    {
        CMutableTransaction tx = SpendOf(COutPoint(), coinbaseSpk);
        const CScript ws = CScript() << TemplateOf(tx, SEEDED) << OP_CHECKTEMPLATEVERIFY;
        tx.vin[0].prevout = SeedCoin(V6ProgramFor(ws), SEEDED, 0xa2);
        SetWitness(tx, {}, ws, trailer);
        BOOST_CHECK_EQUAL(RelayRefusal(tx), MandatoryRefusal(SCRIPT_ERR_DISALLOWED_OPCODE));
        BOOST_CHECK(!BlockIsValid(std::vector<CMutableTransaction>(1, tx)));
    }

    // The key-hash check with a signature of each anyprevout type.
    unsigned char tag = 0xb0;
    for (int byte : ANYPREVOUT_BYTES) {
        const CScript ws = CScript() << KeyHash(key) << OP_CHECKDILITHIUMKEYHASH << OP_1;
        CMutableTransaction tx = SpendOf(SeedCoin(V6ProgramFor(ws), SEEDED, tag++), coinbaseSpk);
        const uint256 sighash = SignatureHash(ws, CTransaction(tx), 0, byte, SEEDED, SIGVERSION_WITNESS_V0, nullptr);
        valtype sig;
        BOOST_REQUIRE(coinbaseKey.Sign(sighash, sig));
        sig.push_back(static_cast<unsigned char>(byte));
        SetWitness(tx, {sig, key}, ws, trailer);
        const std::string refusal = RelayRefusal(tx);
        BOOST_CHECK_MESSAGE(refusal == MandatoryRefusal(SCRIPT_ERR_SIG_HASHTYPE),
            "hash type 0x" << std::hex << byte << std::dec << " at relay: got \"" << refusal << "\"");
        BOOST_CHECK_MESSAGE(!BlockIsValid(std::vector<CMutableTransaction>(1, tx)),
            "hash type 0x" << std::hex << byte << std::dec << " in a block");
    }

    // The product INT64_MIN.
    {
        const CScript ws = CScript() << CScriptNum(-int64_t(4294967296LL)) << CScriptNum(int64_t(2147483648LL)) << OP_MUL;
        CMutableTransaction tx = SpendOf(SeedCoin(V6ProgramFor(ws), SEEDED, 0xa3), coinbaseSpk);
        SetWitness(tx, {}, ws, trailer);
        BOOST_CHECK_EQUAL(RelayRefusal(tx), MandatoryRefusal(SCRIPT_ERR_PUSH_SIZE));
        BOOST_CHECK(!BlockIsValid(std::vector<CMutableTransaction>(1, tx)));
    }

    BOOST_CHECK_EQUAL(mempool.size(), 0u);

    // The same output form with an ordinary signature is relayed and mined, so
    // each refusal above is the rule's and not the fixture's.
    {
        const CScript ws = CScript() << KeyHash(key) << OP_CHECKDILITHIUMKEYHASH << OP_1;
        CMutableTransaction tx = SpendOf(SeedCoin(V6ProgramFor(ws), SEEDED, 0xa4), coinbaseSpk);
        const uint256 sighash = SignatureHash(ws, CTransaction(tx), 0, SIGHASH_ALL, SEEDED, SIGVERSION_WITNESS_V0, nullptr);
        valtype sig;
        BOOST_REQUIRE(coinbaseKey.Sign(sighash, sig));
        sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));
        SetWitness(tx, {sig, key}, ws, trailer);
        BOOST_CHECK(BlockIsValid(std::vector<CMutableTransaction>(1, tx)));
        BOOST_CHECK_EQUAL(RelayRefusal(tx), std::string());
        BOOST_CHECK_EQUAL(mempool.size(), 1u);
    }
}

BOOST_AUTO_TEST_SUITE_END()
