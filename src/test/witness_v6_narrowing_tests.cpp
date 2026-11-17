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
// One exception is in the code: on stagenet two blocks hold a version 6 spend
// signed with an anyprevout type from before the refusal. ConnectBlock sets a
// flag for a block whose hash is on the network's list, and under it the
// key-hash check accepts such a signature.
//
// Three suites. The first drives VerifyScript with stated flags. The second
// spends a version 6 output on a regtest chain through the mempool and through
// a block, and connects a block whose hash is on the list. The third covers
// the list, its one writer and the two stagenet transactions as they are on
// that chain.

#include "amount.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "hash.h"
#include "key.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "streams.h"
#include "test/dilithium_chain_setup.h"
#include "test/test_bitcoin.h"
#include "test/witness_v6_history_data.h"
#include "txmempool.h"
#include "uint256.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "version.h"

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

    //! The witness: the items, the script and a trailer.
    CScriptWitness Witness() const
    {
        CScriptWitness w;
        for (const valtype& v : items)
            w.stack.push_back(v);
        w.stack.push_back(valtype(ws.begin(), ws.end()));
        w.stack.push_back(valtype(1313, 0x00));
        return w;
    }

    //! The sigop count of the input, as GetTransactionSigOpCost reads it.
    size_t SigOps(unsigned int flags) const
    {
        const CScriptWitness w = Witness();
        return CountWitnessSigOps(CScript(), V6ProgramFor(ws), &w, flags);
    }

    ScriptError Verdict(unsigned int flags) const
    {
        const CScriptWitness w = Witness();
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

    // The hash type is refused before the signature is checked: a signature
    // that does not verify gets the error of its hash type, where the same
    // bytes under SIGHASH_ALL get the error of the check.
    for (int byte : ANYPREVOUT_BYTES) {
        Spend forged = TwoOfTwo(a, b, byte);
        forged.items[2][7] ^= 0x01;
        BOOST_CHECK_MESSAGE(forged.Verdict(SWAP_FLAGS | SCRIPT_VERIFY_APO) == SCRIPT_ERR_SIG_HASHTYPE,
            "a forged signature of hash type 0x" << std::hex << byte << std::dec << ": got "
                                                  << Name(forged.Verdict(SWAP_FLAGS | SCRIPT_VERIFY_APO)));
    }
    Spend forgedOrdinary = TwoOfTwo(a, b, SIGHASH_ALL);
    forgedOrdinary.items[2][7] ^= 0x01;
    BOOST_CHECK_EQUAL(forgedOrdinary.Verdict(SWAP_FLAGS | SCRIPT_VERIFY_APO), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
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

// The sigop count of a version 6 input still reads SCRIPT_VERIFY_CSFS: it
// charges an OP_CHECKSIGFROMSTACK byte while the flag is set. A script that
// holds the byte is refused with the flag set and with it clear, so the count
// of a spend that verifies does not depend on the three flags.
BOOST_AUTO_TEST_CASE(the_sigop_count_of_a_v6_spend_that_verifies_does_not_read_the_three_flags)
{
    CKey a, b;
    a.MakeNewKey(true);
    b.MakeNewKey(true);

    struct Row {
        const char* name;
        Spend spend;
        size_t sigops;
    };
    std::vector<Row> accepted;
    // The swap's script holds one key-hash check in each branch.
    accepted.push_back({"the swap's claim", SwapClaim(a, b), 2});
    accepted.push_back({"the swap's refund", SwapRefund(a, b), 2});
    accepted.push_back({"two key-hash checks signed SIGHASH_ALL", TwoOfTwo(a, b, SIGHASH_ALL), 2});

    for (const Row& row : accepted) {
        for (unsigned int mask = 0; mask < 8; ++mask) {
            const unsigned int flags = SWAP_FLAGS | Covenant(mask);
            BOOST_CHECK_MESSAGE(row.spend.Verdict(flags) == SCRIPT_ERR_OK,
                row.name << ", ctv/apo/csfs mask " << mask << ": got " << Name(row.spend.Verdict(flags)));
            BOOST_CHECK_MESSAGE(row.spend.SigOps(flags) == row.sigops,
                row.name << ", ctv/apo/csfs mask " << mask << ": " << row.spend.SigOps(flags) << " sigops, expected "
                         << row.sigops);
        }
    }

    // The byte the count charges under csfs, in a script refused in each state.
    const Spend refused = SignedChecksigfromstack(a);
    for (unsigned int mask = 0; mask < 8; ++mask) {
        const unsigned int flags = SWAP_FLAGS | Covenant(mask);
        BOOST_CHECK_EQUAL(refused.Verdict(flags), SCRIPT_ERR_DISALLOWED_OPCODE);
        BOOST_CHECK_EQUAL(refused.SigOps(flags), (mask & 4) ? 1u : 0u);
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

//! Whether a solved block passes ConnectBlock on the tip.
bool Connects(const CBlock& block)
{
    CValidationState st;
    LOCK(cs_main);
    return TestBlockValidity(st, Params(), block, chainActive.Tip(), true, true);
}

//! Puts one hash on regtest's list, on the tier of one height, and takes it
//! off when the case ends. The node has no function that alters a network's
//! list: chainparams.cpp fills stagenet's when the parameters are built.
struct ListedForTheCase {
    std::set<uint256>& list;
    const uint256 hash;

    ListedForTheCase(const uint256& hashIn, int height)
        : list(const_cast<Consensus::Params&>(Params().GetConsensus(height)).witnessV6AnyprevoutHistoryBlocks),
          hash(hashIn)
    {
        BOOST_REQUIRE(list.empty());
        list.insert(hash);
    }
    ~ListedForTheCase() { list.erase(hash); }
};

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

// The call site of the one writer. ConnectBlock reads the list of the network
// it validates with the hash of the block it connects, so a block on the list
// takes a version 6 spend signed with an anyprevout type and a block with any
// other hash does not. Regtest's list is empty: the case puts the hash of one
// solved block on it for the length of the check.
BOOST_AUTO_TEST_CASE(connectblock_takes_an_anyprevout_spend_in_a_listed_block_and_in_no_other)
{
    const valtype key = coinbasePkBytes;
    const valtype trailer = PrefixedPubkey(coinbasePkBytes);
    const CScript ws = CScript() << KeyHash(key) << OP_CHECKDILITHIUMKEYHASH << OP_1;
    CMutableTransaction tx = SpendOf(SeedCoin(V6ProgramFor(ws), SEEDED, 0xc0), coinbaseSpk);
    const uint256 sighash = SignatureHash(ws, CTransaction(tx), 0, SIGHASH_ANYPREVOUTANYSCRIPT, SEEDED,
                                          SIGVERSION_WITNESS_V0, nullptr);
    valtype sig;
    BOOST_REQUIRE(coinbaseKey.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ANYPREVOUTANYSCRIPT));
    SetWitness(tx, {sig, key}, ws, trailer);

    // Two solved blocks that hold the spend and differ in their nonce.
    const CBlock listed = BuildSolvedBlock(std::vector<CMutableTransaction>(1, tx), coinbaseSpk);
    CBlock other = listed;
    do {
        ++other.nNonce;
    } while (!CheckProofOfWork(other.GetPoWHash(), other.nBits, Params().GetConsensus(0)));
    BOOST_REQUIRE(other.GetHash() != listed.GetHash());

    int height = 0;
    {
        LOCK(cs_main);
        height = chainActive.Height() + 1;
    }
    BOOST_REQUIRE(Params().GetConsensus(height).witnessV6AnyprevoutHistoryBlocks.empty());
    BOOST_CHECK(!Connects(listed));
    BOOST_CHECK(!Connects(other));

    {
        const ListedForTheCase entry(listed.GetHash(), height);
        BOOST_CHECK(Connects(listed));
        BOOST_CHECK(!Connects(other));
        // The mempool does not read the list.
        BOOST_CHECK_EQUAL(RelayRefusal(tx), MandatoryRefusal(SCRIPT_ERR_SIG_HASHTYPE));
        BOOST_CHECK_EQUAL(mempool.size(), 0u);
    }

    BOOST_CHECK(Params().GetConsensus(height).witnessV6AnyprevoutHistoryBlocks.empty());
    BOOST_CHECK(!Connects(listed));
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// The history list: the blocks in which the version 6 key-hash check accepts
// an anyprevout hash type.
// ---------------------------------------------------------------------------
BOOST_FIXTURE_TEST_SUITE(witness_v6_history_tests, BasicTestingSetup)

namespace {

//! Selects a network for one case and returns to the fixture's.
struct Network {
    explicit Network(const std::string& name) { SelectParams(name); }
    ~Network() { SelectParams(CBaseChainParams::MAIN); }
};

const char* const NETWORKS[] = {"main", "test", "regtest", "stagenet"};

//! Heights on both sides of every tier boundary of every network.
const int HEIGHTS[] = {0, 1, 9, 10, 11, 19, 20, 21, 99, 100, 101, 1056, 1057, 1058, 1063, 1064, 1065,
                       99999, 100000, 100001, 1000000};

const uint256 BLOCK_1057 = uint256S("0xb6eceab13b813a7f4600b92d86df852cb86222fe574582e280a777f5a84c6c5e");
const uint256 BLOCK_1064 = uint256S("0x39c7a32ab8447f2d15711181ad9c03ae1cb34593813f67e97ef7d6e2746d5e7e");

//! One of the two stagenet spends: the transaction, the output it spends and
//! the block that holds it.
struct Historic {
    const char* hex;
    const char* txid;
    const char* spk;
    int height;
    uint256 block;
};

std::vector<Historic> TheTwoSpends()
{
    std::vector<Historic> v;
    v.push_back({STAGENET_BLOCK_1057_SPEND, "e188cd62c2d37f43fcb22747f5c872f8a0d025b3611c489d76827b7f5126653b",
                 "562024c63134743e8a2c1ff053176c6a1b11e5a84f9db64155d0dd14f2b442535e5d", 1057, BLOCK_1057});
    v.push_back({STAGENET_BLOCK_1064_SPEND, "6cd821e8cf0dad85fd50e3bc0af4bfb7e6ec6cb9bc3890260feb0dca3f4c1e0e",
                 "5620f4410d1155072cee767a366798f0a7afabe3031651c1b305e03b6970cf54a7b6", 1064, BLOCK_1064});
    return v;
}

//! Each spent output held one coin.
const CAmount HISTORIC_AMOUNT = COIN;

ScriptError VerdictOf(const Historic& h, unsigned int flags)
{
    CDataStream ss(ParseHex(h.hex), SER_NETWORK, PROTOCOL_VERSION);
    CMutableTransaction mtx;
    ss >> mtx;
    const CTransaction tx(mtx);
    BOOST_REQUIRE_EQUAL(tx.GetHash().GetHex(), std::string(h.txid));
    BOOST_REQUIRE_EQUAL(tx.vin.size(), 1u);
    const std::vector<unsigned char> spkBytes = ParseHex(h.spk);
    const CScript spk(spkBytes.begin(), spkBytes.end());
    const PrecomputedTransactionData txdata(tx);
    const TransactionSignatureChecker checker(&tx, 0, HISTORIC_AMOUNT, txdata);
    ScriptError serr = SCRIPT_ERR_OK;
    VerifyScript(tx.vin[0].scriptSig, spk, &tx.vin[0].scriptWitness, flags, checker, &serr);
    return serr;
}

//! Some hashes that are not on the list: the null hash, the network's genesis
//! block, and each listed hash with one byte changed and with its bytes
//! reversed.
std::vector<uint256> OtherHashes(const Consensus::Params& consensus)
{
    std::vector<uint256> v;
    v.push_back(uint256());
    v.push_back(consensus.hashGenesisBlock);
    for (const uint256& listed : {BLOCK_1057, BLOCK_1064}) {
        uint256 changed = listed;
        changed.begin()[0] ^= 0x01;
        v.push_back(changed);
        uint256 reversed;
        for (int i = 0; i < 32; ++i)
            reversed.begin()[i] = listed.begin()[31 - i];
        v.push_back(reversed);
    }
    return v;
}

} // namespace

BOOST_AUTO_TEST_CASE(the_list_holds_two_stagenet_blocks_and_none_elsewhere)
{
    for (const char* network : NETWORKS) {
        const Network selected(network);
        for (int height : HEIGHTS) {
            const std::set<uint256>& list = Params().GetConsensus(height).witnessV6AnyprevoutHistoryBlocks;
            if (std::string(network) == "stagenet") {
                BOOST_CHECK_MESSAGE(list.size() == 2 && list.count(BLOCK_1057) == 1 && list.count(BLOCK_1064) == 1,
                    "stagenet, the tier of height " << height << ": " << list.size() << " entries");
            } else {
                BOOST_CHECK_MESSAGE(list.empty(), network << ", the tier of height " << height << ": "
                                                          << list.size() << " entries");
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(the_writer_sets_the_flag_for_the_two_hashes_on_stagenet_alone)
{
    for (const char* network : NETWORKS) {
        const Network selected(network);
        const bool stagenet = std::string(network) == "stagenet";
        for (int height : HEIGHTS) {
            const Consensus::Params& consensus = Params().GetConsensus(height);
            for (const uint256& listed : {BLOCK_1057, BLOCK_1064}) {
                BOOST_CHECK_MESSAGE(
                    WitnessV6HistoryFlags(listed, consensus) == (stagenet ? (unsigned int)SCRIPT_VERIFY_V6_ANYPREVOUT_HISTORY : 0u),
                    network << ", the tier of height " << height << ", block " << listed.GetHex());
            }
            for (const uint256& other : OtherHashes(consensus)) {
                BOOST_CHECK_MESSAGE(WitnessV6HistoryFlags(other, consensus) == 0u,
                    network << ", the tier of height " << height << ", hash " << other.GetHex());
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(the_flag_is_in_neither_policy_set_and_shares_its_bit_with_no_other_flag)
{
    BOOST_CHECK_EQUAL(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_V6_ANYPREVOUT_HISTORY, 0u);
    BOOST_CHECK_EQUAL(MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_V6_ANYPREVOUT_HISTORY, 0u);

    const unsigned int others =
        SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S |
        SCRIPT_VERIFY_NULLDUMMY | SCRIPT_VERIFY_SIGPUSHONLY | SCRIPT_VERIFY_MINIMALDATA |
        SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS | SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
        SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
        SCRIPT_VERIFY_MINIMALIF | SCRIPT_VERIFY_NULLFAIL | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE |
        SCRIPT_VERIFY_LATTICEFOLD | SCRIPT_VERIFY_PAT | SCRIPT_VERIFY_SOQUOBSCURA | SCRIPT_VERIFY_USDSOQ |
        SCRIPT_VERIFY_CTV | SCRIPT_VERIFY_APO | SCRIPT_VERIFY_CSFS | SCRIPT_VERIFY_SCRIPT_RESTORE |
        SCRIPT_VERIFY_P2WSH_DILITHIUM | SCRIPT_VERIFY_DILITHIUM_KEYHASH | SCRIPT_VERIFY_V6_CONTROLFLOW |
        SCRIPT_VERIFY_BTCSOQ;
    BOOST_CHECK_EQUAL(others & SCRIPT_VERIFY_V6_ANYPREVOUT_HISTORY, 0u);
    BOOST_CHECK_EQUAL((unsigned int)SCRIPT_VERIFY_V6_ANYPREVOUT_HISTORY, 1U << 28);
}

// The two transactions verify under the flags of their blocks, which carry
// the flag for those two hashes, and are refused under the flags of any other
// block and of any other network.
BOOST_AUTO_TEST_CASE(the_two_stagenet_spends_verify_in_their_blocks_and_in_no_other)
{
    for (const Historic& h : TheTwoSpends()) {
        unsigned int blockFlags = 0;
        unsigned int historyFlag = 0;
        std::vector<uint256> others;
        {
            const Network selected("stagenet");
            const Consensus::Params& consensus = Params().GetConsensus(h.height);
            // The six deployments begin at height 0 on stagenet.
            BOOST_REQUIRE_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_P2WSH_DILITHIUM].nActivationHeight, 0);
            BOOST_REQUIRE_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nActivationHeight, 0);
            BOOST_REQUIRE_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_V6_CONTROLFLOW].nActivationHeight, 0);
            BOOST_REQUIRE_EQUAL(WitnessV11DeploymentFlags(h.height, consensus),
                                (unsigned int)(SCRIPT_VERIFY_CTV | SCRIPT_VERIFY_APO | SCRIPT_VERIFY_CSFS));
            blockFlags = SWAP_FLAGS | WitnessV11DeploymentFlags(h.height, consensus);
            historyFlag = WitnessV6HistoryFlags(h.block, consensus);
            others = OtherHashes(consensus);
            for (const uint256& other : others)
                BOOST_CHECK_EQUAL(VerdictOf(h, blockFlags | WitnessV6HistoryFlags(other, consensus)),
                                  SCRIPT_ERR_SIG_HASHTYPE);
        }
        BOOST_CHECK_EQUAL(historyFlag, (unsigned int)SCRIPT_VERIFY_V6_ANYPREVOUT_HISTORY);
        BOOST_CHECK_EQUAL(VerdictOf(h, blockFlags | historyFlag), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(VerdictOf(h, blockFlags), SCRIPT_ERR_SIG_HASHTYPE);

        // The same block hash under the parameters of the other networks.
        for (const char* network : {"main", "test", "regtest"}) {
            const Network selected(network);
            const Consensus::Params& consensus = Params().GetConsensus(h.height);
            BOOST_CHECK_MESSAGE(VerdictOf(h, blockFlags | WitnessV6HistoryFlags(h.block, consensus)) == SCRIPT_ERR_SIG_HASHTYPE,
                network << ": the spend of block " << h.height);
        }
    }
}

// Under the flag the key-hash check accepts an anyprevout type, and nothing
// else is accepted that is refused without it.
BOOST_AUTO_TEST_CASE(the_flag_widens_the_keyhash_check_and_nothing_else)
{
    CKey a, b;
    a.MakeNewKey(true);
    b.MakeNewKey(true);

    Spend product;
    product.ws = CScript() << CScriptNum(-int64_t(4294967296LL)) << CScriptNum(int64_t(2147483648LL)) << OP_MUL;

    for (unsigned int mask = 0; mask < 8; ++mask) {
        const unsigned int with = SWAP_FLAGS | Covenant(mask) | SCRIPT_VERIFY_V6_ANYPREVOUT_HISTORY;
        BOOST_CHECK_EQUAL(SignedChecksigfromstack(a).Verdict(with), SCRIPT_ERR_DISALLOWED_OPCODE);
        BOOST_CHECK_EQUAL(MatchingTemplate().Verdict(with), SCRIPT_ERR_DISALLOWED_OPCODE);
        BOOST_CHECK_EQUAL(product.Verdict(with), SCRIPT_ERR_PUSH_SIZE);
        BOOST_CHECK_EQUAL(TwoOfTwo(a, b, SIGHASH_ALL).Verdict(with), SCRIPT_ERR_OK);
        for (int byte : {0x41, 0x42}) {
            const Spend s = TwoOfTwo(a, b, byte);
            BOOST_CHECK_EQUAL(s.Verdict(with), SCRIPT_ERR_OK);
            BOOST_CHECK_EQUAL(s.Verdict(with & ~SCRIPT_VERIFY_V6_ANYPREVOUT_HISTORY), SCRIPT_ERR_SIG_HASHTYPE);
        }
        // A signature that does not verify is refused under the flag as well.
        Spend forged = TwoOfTwo(a, b, SIGHASH_ANYPREVOUTANYSCRIPT);
        forged.items[0][7] ^= 0x01;
        BOOST_CHECK_EQUAL(forged.Verdict(with), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
    }
}

BOOST_AUTO_TEST_SUITE_END()
