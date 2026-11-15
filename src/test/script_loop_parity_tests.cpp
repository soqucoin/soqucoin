// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// script_loop_parity_tests.cpp — what the script loop pushes, when it runs an
// opcode, and what OP_CHECKTEMPLATEVERIFY compares against.
//
// Witness versions 6 and 11 run their scripts through one loop, EvalScript.
// Three of its properties are held here against statements of them that share
// no code with the interpreter:
//
//   - a number is pushed as its sign-and-magnitude encoding. The product
//     INT64_MIN of OP_MUL is the one number that takes nine bytes;
//   - an opcode runs when no enclosing branch is false, with the nesting kept
//     as a list of booleans that is read from end to end;
//   - the template hash of a transaction at an input is the written format,
//     whether or not the checker holds the transaction's precomputed data,
//     which keeps the three parts of the hash that are the same for every
//     input, so that a checker that holds it reads no script of the
//     transaction.
//
// The last case pins a digest for each of three families of generated
// scripts: every verdict, error and final stack, hashed. A change to the loop
// that alters none of them leaves the three digests where they are.

#include "amount.h"
#include "crypto/sha256.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace {

typedef std::vector<unsigned char> valtype;

//! The flags of a block on a network where the deployments of witness
//! versions 6 and 11 are active.
const unsigned int ACTIVE = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                            SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_SCRIPT_RESTORE |
                            SCRIPT_VERIFY_P2WSH_DILITHIUM | SCRIPT_VERIFY_DILITHIUM_KEYHASH |
                            SCRIPT_VERIFY_V6_CONTROLFLOW | SCRIPT_VERIFY_CTV | SCRIPT_VERIFY_APO | SCRIPT_VERIFY_CSFS;

const CAmount AMOUNT = 50 * COIN;

//! A generator whose output is the same on every platform (splitmix64).
struct Generator {
    uint64_t state;
    explicit Generator(uint64_t seed) : state(seed) {}
    uint64_t Next()
    {
        uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }
    //! A value in [0, n).
    uint64_t Below(uint64_t n) { return Next() % n; }
    valtype Bytes(size_t n)
    {
        valtype out(n);
        for (size_t i = 0; i < n; ++i)
            out[i] = static_cast<unsigned char>(Next() & 0xff);
        return out;
    }
};

//! The encoding of a script number, written without negating a signed value:
//! the magnitude with its least significant byte first, the sign in the top
//! bit of the last byte, and one byte more when the magnitude uses that bit.
valtype NumberEncoding(int64_t value)
{
    valtype out;
    if (value == 0)
        return out;
    const bool negative = value < 0;
    // For a negative value, -(value + 1) is at most INT64_MAX.
    uint64_t magnitude = negative ? static_cast<uint64_t>(-(value + 1)) + 1 : static_cast<uint64_t>(value);
    while (magnitude) {
        out.push_back(static_cast<unsigned char>(magnitude & 0xff));
        magnitude >>= 8;
    }
    if (out.back() & 0x80)
        out.push_back(negative ? 0x80 : 0x00);
    else if (negative)
        out.back() |= 0x80;
    return out;
}

//! Whether a stack item is true: a byte that is not zero, other than the sign
//! byte of a negative zero.
bool Truth(const valtype& item)
{
    for (size_t i = 0; i < item.size(); ++i) {
        if (item[i] != 0)
            return !(i == item.size() - 1 && item[i] == 0x80);
    }
    return false;
}

valtype Sha256(const valtype& data)
{
    valtype h(32);
    CSHA256 hasher;
    if (!data.empty())
        hasher.Write(data.data(), data.size());
    hasher.Finalize(h.data());
    return h;
}

//! The verdict of `script` spent as an output of witness version 6. The
//! witness is the satisfaction items, the script and a trailer.
ScriptError V6Verdict(const CScript& script, const std::vector<valtype>& items = std::vector<valtype>())
{
    CScriptWitness w;
    w.stack = items;
    w.stack.push_back(valtype(script.begin(), script.end()));
    w.stack.push_back(valtype(1313, 0x00));
    const CScript output = CScript() << OP_6 << Sha256(valtype(script.begin(), script.end()));
    BaseSignatureChecker checker;
    ScriptError serr = SCRIPT_ERR_OK;
    VerifyScript(CScript(), output, &w, ACTIVE, checker, &serr);
    return serr;
}

//! The verdict of `script` spent as an output of witness version 11. The
//! witness is the satisfaction items, the committed item (the sub-version byte
//! 0xc0 and the script) and the trailer 0x00.
ScriptError V11Verdict(const CScript& script, const std::vector<valtype>& items = std::vector<valtype>())
{
    valtype committed(1, 0xc0);
    committed.insert(committed.end(), script.begin(), script.end());
    CScriptWitness w;
    w.stack = items;
    w.stack.push_back(committed);
    w.stack.push_back(valtype(1, 0x00));
    const CScript output = CScript() << OP_11 << Sha256(committed);
    BaseSignatureChecker checker;
    ScriptError serr = SCRIPT_ERR_OK;
    VerifyScript(CScript(), output, &w, ACTIVE, checker, &serr);
    return serr;
}

std::string Name(ScriptError e) { return std::string(ScriptErrorString(e)); }

//! One run of the loop: what EvalScript returned, its error and the stack it left.
struct Outcome {
    bool ok;
    ScriptError error;
    std::vector<valtype> stack;
};

Outcome Run(const CScript& script, std::vector<valtype> stack, unsigned int flags, SigVersion sigversion,
            const BaseSignatureChecker& checker = BaseSignatureChecker())
{
    Outcome out;
    out.error = SCRIPT_ERR_OK;
    out.ok = EvalScript(stack, script, flags, checker, sigversion, &out.error);
    out.stack = stack;
    return out;
}

// ---------------------------------------------------------------------------
// Conditionals: a sequence of OP_IF, OP_NOTIF, OP_ELSE and OP_ENDIF, each
// followed by the push of a marker of its own. The markers left on the stack
// say after which of them the script was executing.
// ---------------------------------------------------------------------------

enum TokenKind { TOKEN_IF, TOKEN_NOTIF, TOKEN_ELSE, TOKEN_ENDIF };

struct Token {
    TokenKind kind;
    bool hasArgument;  //!< for OP_IF and OP_NOTIF: whether a push of `argument` precedes it
    valtype argument;
};

//! The marker pushed after token `i`: two bytes, never zero.
valtype Marker(size_t i)
{
    valtype m(2);
    m[0] = static_cast<unsigned char>((i + 1) & 0xff);
    m[1] = static_cast<unsigned char>(0x40 | (((i + 1) >> 8) & 0x3f));
    return m;
}

CScript ScriptOf(const std::vector<Token>& tokens)
{
    CScript script;
    for (size_t i = 0; i < tokens.size(); ++i) {
        const Token& t = tokens[i];
        if ((t.kind == TOKEN_IF || t.kind == TOKEN_NOTIF) && t.hasArgument)
            script << t.argument;
        switch (t.kind) {
        case TOKEN_IF: script << OP_IF; break;
        case TOKEN_NOTIF: script << OP_NOTIF; break;
        case TOKEN_ELSE: script << OP_ELSE; break;
        case TOKEN_ENDIF: script << OP_ENDIF; break;
        }
        script << Marker(i);
    }
    return script;
}

//! What the sequence does, by the rule as it is written: the nesting is a list
//! of booleans, and the script is executing when the list holds no false.
//! `minimalArgument` is the rule that the argument of a branch is the empty
//! item or the one byte 0x01.
Outcome Model(const std::vector<Token>& tokens, bool minimalArgument)
{
    Outcome out;
    out.ok = false;
    out.error = SCRIPT_ERR_OK;
    std::vector<bool> nesting;
    auto executing = [&nesting]() {
        for (size_t i = 0; i < nesting.size(); ++i)
            if (!nesting[i])
                return false;
        return true;
    };
    for (size_t i = 0; i < tokens.size(); ++i) {
        const Token& t = tokens[i];
        if (t.kind == TOKEN_IF || t.kind == TOKEN_NOTIF) {
            if (t.hasArgument && executing())
                out.stack.push_back(t.argument);
            bool value = false;
            if (executing()) {
                if (out.stack.empty()) {
                    out.error = SCRIPT_ERR_UNBALANCED_CONDITIONAL;
                    return out;
                }
                const valtype& top = out.stack.back();
                if (minimalArgument && (top.size() > 1 || (top.size() == 1 && top[0] != 1))) {
                    out.error = SCRIPT_ERR_MINIMALIF;
                    return out;
                }
                value = Truth(top);
                if (t.kind == TOKEN_NOTIF)
                    value = !value;
                out.stack.pop_back();
            }
            nesting.push_back(value);
        } else if (t.kind == TOKEN_ELSE) {
            if (nesting.empty()) {
                out.error = SCRIPT_ERR_UNBALANCED_CONDITIONAL;
                return out;
            }
            nesting.back() = !nesting.back();
        } else {
            if (nesting.empty()) {
                out.error = SCRIPT_ERR_UNBALANCED_CONDITIONAL;
                return out;
            }
            nesting.pop_back();
        }
        if (executing())
            out.stack.push_back(Marker(i));
    }
    if (!nesting.empty()) {
        out.error = SCRIPT_ERR_UNBALANCED_CONDITIONAL;
        return out;
    }
    if (out.stack.empty()) {
        out.error = SCRIPT_ERR_EVAL_FALSE;
        return out;
    }
    out.ok = true;
    return out;
}

//! The arguments a generated branch is given: the two the minimal rule
//! admits, and six it does not, three of them false.
const char* const ARGUMENTS[] = {"", "01", "02", "00", "80", "0100", "0000", "0080"};

//! A generated sequence. While no conditional is open it mostly opens one;
//! four in five sequences close what they opened.
std::vector<Token> GenerateTokens(Generator& gen)
{
    std::vector<Token> tokens;
    const size_t length = 1 + gen.Below(48);
    size_t depth = 0;
    for (size_t i = 0; i < length; ++i) {
        const uint64_t r = gen.Below(100);
        Token t;
        t.hasArgument = false;
        if (depth == 0)
            t.kind = r < 60 ? TOKEN_IF : r < 90 ? TOKEN_NOTIF : r < 95 ? TOKEN_ELSE : TOKEN_ENDIF;
        else
            t.kind = r < 25 ? TOKEN_IF : r < 40 ? TOKEN_NOTIF : r < 70 ? TOKEN_ELSE : TOKEN_ENDIF;
        if (t.kind == TOKEN_IF || t.kind == TOKEN_NOTIF) {
            t.hasArgument = gen.Below(10) != 0;
            // Three in four arguments are one of the two the minimal rule admits.
            const size_t pick = gen.Below(4) != 0 ? gen.Below(2) : gen.Below(sizeof(ARGUMENTS) / sizeof(ARGUMENTS[0]));
            t.argument = ParseHex(ARGUMENTS[pick]);
            ++depth;
        } else if (t.kind == TOKEN_ENDIF && depth > 0) {
            --depth;
        }
        tokens.push_back(t);
    }
    if (gen.Below(5) != 0) {
        for (; depth > 0; --depth) {
            Token t;
            t.kind = TOKEN_ENDIF;
            t.hasArgument = false;
            tokens.push_back(t);
        }
    }
    return tokens;
}

// ---------------------------------------------------------------------------
// The template hash, from the written format.
// ---------------------------------------------------------------------------

void WriteLE32(CSHA256& h, uint32_t v)
{
    const unsigned char b[4] = {static_cast<unsigned char>(v), static_cast<unsigned char>(v >> 8),
                                static_cast<unsigned char>(v >> 16), static_cast<unsigned char>(v >> 24)};
    h.Write(b, 4);
}

void WriteLE64(CSHA256& h, uint64_t v)
{
    unsigned char b[8];
    for (int i = 0; i < 8; ++i)
        b[i] = static_cast<unsigned char>(v >> (8 * i));
    h.Write(b, 8);
}

void WriteScript(CSHA256& h, const CScript& script)
{
    WriteLE32(h, static_cast<uint32_t>(script.size()));
    if (!script.empty())
        h.Write(script.data(), script.size());
}

//! Whether the scriptSig of an input of `tx` is not empty.
bool AnyScriptSig(const CTransaction& tx)
{
    for (const CTxIn& in : tx.vin)
        if (!in.scriptSig.empty())
            return true;
    return false;
}

//! The SHA-256 of the scriptSigs of `tx`, each written after its length.
valtype ScriptSigsPart(const CTransaction& tx)
{
    CSHA256 h;
    for (const CTxIn& in : tx.vin)
        WriteScript(h, in.scriptSig);
    valtype out(32);
    h.Finalize(out.data());
    return out;
}

//! The SHA-256 of the sequences of `tx`, four bytes each.
valtype SequencesPart(const CTransaction& tx)
{
    CSHA256 h;
    for (const CTxIn& in : tx.vin)
        WriteLE32(h, in.nSequence);
    valtype out(32);
    h.Finalize(out.data());
    return out;
}

//! The SHA-256 of the outputs of `tx`: the value as eight bytes, then the
//! script after its length.
valtype OutputsPart(const CTransaction& tx)
{
    CSHA256 h;
    for (const CTxOut& out : tx.vout) {
        WriteLE64(h, static_cast<uint64_t>(out.nValue));
        WriteScript(h, out.scriptPubKey);
    }
    valtype out(32);
    h.Finalize(out.data());
    return out;
}

//! The template hash of `tx` at input `nIn`: the version, the lock time, the
//! hash of the scriptSigs when one of them is not empty, the number of
//! inputs, the hash of the sequences, the number of outputs, the hash of the
//! outputs, the input's index. Each script is written after its length as
//! four bytes.
valtype TemplateHash(const CTransaction& tx, uint32_t nIn)
{
    CSHA256 h;
    WriteLE32(h, static_cast<uint32_t>(tx.nVersion));
    WriteLE32(h, tx.nLockTime);
    if (AnyScriptSig(tx))
        h.Write(ScriptSigsPart(tx).data(), 32);
    WriteLE32(h, static_cast<uint32_t>(tx.vin.size()));
    h.Write(SequencesPart(tx).data(), 32);
    WriteLE32(h, static_cast<uint32_t>(tx.vout.size()));
    h.Write(OutputsPart(tx).data(), 32);
    WriteLE32(h, nIn);
    valtype result(32);
    h.Finalize(result.data());
    return result;
}

//! Which inputs of a generated transaction carry a scriptSig.
enum ScriptSigPattern { SCRIPTSIG_NONE, SCRIPTSIG_ALL, SCRIPTSIG_FIRST, SCRIPTSIG_LAST, SCRIPTSIG_SOME, SCRIPTSIG_PATTERNS };

CMutableTransaction GenerateTx(Generator& gen, ScriptSigPattern pattern)
{
    static const int32_t VERSIONS[] = {1, 2, 3, -1, std::numeric_limits<int32_t>::max()};
    CMutableTransaction tx;
    tx.nVersion = VERSIONS[gen.Below(sizeof(VERSIONS) / sizeof(VERSIONS[0]))];
    tx.nLockTime = static_cast<uint32_t>(gen.Next());
    const size_t inputs = 1 + gen.Below(6);
    const size_t outputs = gen.Below(6);
    for (size_t i = 0; i < inputs; ++i) {
        CTxIn in;
        const valtype txid = gen.Bytes(32);
        in.prevout = COutPoint(uint256(txid), static_cast<uint32_t>(gen.Below(4)));
        in.nSequence = static_cast<uint32_t>(gen.Next());
        const bool carries = pattern == SCRIPTSIG_ALL || (pattern == SCRIPTSIG_FIRST && i == 0) ||
                             (pattern == SCRIPTSIG_LAST && i == inputs - 1) ||
                             (pattern == SCRIPTSIG_SOME && gen.Below(2) == 0);
        if (carries) {
            const valtype bytes = gen.Bytes(1 + gen.Below(gen.Below(8) == 0 ? 700 : 40));
            in.scriptSig = CScript(bytes.begin(), bytes.end());
        }
        tx.vin.push_back(in);
    }
    for (size_t i = 0; i < outputs; ++i) {
        const valtype bytes = gen.Bytes(gen.Below(60));
        tx.vout.push_back(CTxOut(static_cast<CAmount>(gen.Next() >> 1), CScript(bytes.begin(), bytes.end())));
    }
    return tx;
}

// ---------------------------------------------------------------------------
// The digest of a family: every outcome, hashed.
// ---------------------------------------------------------------------------

void Record(CSHA256& digest, const Outcome& out, size_t& succeeded)
{
    succeeded += out.ok ? 1 : 0;
    const unsigned char ok = out.ok ? 1 : 0;
    digest.Write(&ok, 1);
    WriteLE32(digest, static_cast<uint32_t>(out.error));
    WriteLE32(digest, static_cast<uint32_t>(out.stack.size()));
    for (const valtype& item : out.stack) {
        WriteLE32(digest, static_cast<uint32_t>(item.size()));
        if (!item.empty())
            digest.Write(item.data(), item.size());
    }
}

std::string Hex(CSHA256& digest)
{
    unsigned char out[32];
    digest.Finalize(out);
    return HexStr(out, out + 32);
}

//! The numbers the arithmetic family multiplies and divides: zero, each power
//! of two below 2^63, the two neighbours of seven of them, and the largest
//! value an operand of eight bytes holds, each with either sign.
std::vector<int64_t> Operands()
{
    std::vector<int64_t> v;
    v.push_back(0);
    for (int k = 0; k <= 62; ++k) {
        const int64_t p = int64_t(1) << k;
        v.push_back(p);
        v.push_back(-p);
        if (k == 7 || k == 8 || k == 15 || k == 16 || k == 31 || k == 32 || k == 62) {
            for (int64_t x : {p - 1, p + 1}) {
                v.push_back(x);
                v.push_back(-x);
            }
        }
    }
    v.push_back(std::numeric_limits<int64_t>::max());
    v.push_back(-std::numeric_limits<int64_t>::max());
    return v;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(script_loop_parity_tests, BasicTestingSetup)

// CScriptNum::serialize against the encoding written above, over the edges of
// the range and over generated values. One value takes nine bytes, INT64_MIN.
// Every other encoding is at most eight bytes, is minimal and decodes to the
// value it was made from.
BOOST_AUTO_TEST_CASE(a_number_is_pushed_as_its_sign_and_magnitude)
{
    const int64_t lowest = std::numeric_limits<int64_t>::min();
    const int64_t highest = std::numeric_limits<int64_t>::max();

    std::vector<int64_t> values = {lowest, lowest + 1, lowest + 2, -1, 0, 1, highest - 1, highest};
    for (int k = 1; k <= 62; ++k) {
        const int64_t p = int64_t(1) << k;
        for (int64_t x : {p - 1, p, p + 1}) {
            values.push_back(x);
            values.push_back(-x);
        }
    }
    Generator gen(0x6e756d62657273ULL);
    for (int i = 0; i < 200000; ++i) {
        // A value of a generated width, so that every length of encoding occurs.
        const int width = 1 + static_cast<int>(gen.Below(64));
        const uint64_t bits = width == 64 ? gen.Next() : gen.Next() & ((uint64_t(1) << width) - 1);
        values.push_back(static_cast<int64_t>(bits));
    }

    size_t nine = 0;
    for (int64_t value : values) {
        const valtype expected = NumberEncoding(value);
        const valtype got = CScriptNum::serialize(value);
        BOOST_REQUIRE_MESSAGE(got == expected,
            "the number " << value << " is encoded as " << HexStr(got) << ", and its encoding is " << HexStr(expected));
        BOOST_CHECK(CScriptNum(value).getvch() == expected);
        if (got.size() > 8) {
            ++nine;
            BOOST_CHECK_EQUAL(value, lowest);
            continue;
        }
        const CScriptNum decoded(got, true, 8);
        BOOST_CHECK_EQUAL(decoded.getint64(), value);
    }
    // INT64_MIN is in the list once and is the one value over eight bytes.
    BOOST_CHECK_EQUAL(nine, 1u);
    BOOST_CHECK(CScriptNum::serialize(lowest) == ParseHex("000000000000008080"));
}

// OP_MUL takes operands of up to eight bytes, and its overflow test admits the
// product INT64_MIN. Witness version 6 pushes that product as nine bytes, for
// each of the 124 pairs of operands that multiply to it, and the item cannot
// be an operand again. Witness version 11 refuses the product.
BOOST_AUTO_TEST_CASE(witness_version_6_pushes_the_product_int64_min_as_nine_bytes)
{
    const valtype nine = ParseHex("000000000000008080");
    int pairs = 0;
    for (int k = 1; k <= 62; ++k) {
        const int64_t x = int64_t(1) << k;
        const int64_t y = int64_t(1) << (63 - k);
        for (int arrangement = 0; arrangement < 2; ++arrangement) {
            const int64_t a = arrangement == 0 ? -x : x;
            const int64_t b = arrangement == 0 ? y : -y;
            ++pairs;
            const CScript equal = CScript() << CScriptNum(a) << CScriptNum(b) << OP_MUL << nine << OP_EQUAL;
            const ScriptError got = V6Verdict(equal);
            BOOST_CHECK_MESSAGE(got == SCRIPT_ERR_OK,
                a << " times " << b << " must leave the nine bytes under witness version 6; got " << Name(got));
            BOOST_CHECK_EQUAL(V11Verdict(equal), SCRIPT_ERR_PUSH_SIZE);
        }
    }
    BOOST_CHECK_EQUAL(pairs, 124);

    const int64_t two32 = int64_t(1) << 32;
    const int64_t two31 = int64_t(1) << 31;
    // The loop itself, under the two signature versions that existed before
    // witness version 11: the stack holds the nine bytes and nothing else.
    for (SigVersion sigversion : {SIGVERSION_BASE, SIGVERSION_WITNESS_V0}) {
        const Outcome out = Run(CScript() << CScriptNum(-two32) << CScriptNum(two31) << OP_MUL, std::vector<valtype>(), ACTIVE, sigversion);
        BOOST_CHECK(out.ok);
        BOOST_CHECK(out.stack == std::vector<valtype>(1, nine));
    }
    // The nine bytes are not a number the next arithmetic opcode takes.
    BOOST_CHECK_EQUAL(V6Verdict(CScript() << CScriptNum(-two32) << CScriptNum(two31) << OP_MUL << OP_1 << OP_MUL << OP_DROP << OP_1),
                      SCRIPT_ERR_UNKNOWN_ERROR);
    // The product beside it is a number of eight bytes: -(2^63 - 2^32).
    const CScript beside = CScript() << CScriptNum(-two32) << CScriptNum(two31 - 1) << OP_MUL
                                     << ParseHex("00000000ffffffff") << OP_EQUAL;
    BOOST_CHECK_EQUAL(V6Verdict(beside), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(V11Verdict(beside), SCRIPT_ERR_OK);
}

// Generated sequences of the four conditional opcodes, each followed by a
// marker, against the rule as it is written: under witness version 6 with and
// without the rule on a branch's argument, and under witness version 11, which
// always has it. The verdict, the error and the markers left are the model's.
BOOST_AUTO_TEST_CASE(an_opcode_runs_when_no_enclosing_branch_is_false)
{
    struct Mode {
        const char* name;
        unsigned int flags;
        SigVersion sigversion;
        bool minimalArgument;
    };
    const Mode modes[] = {
        {"witness version 6", ACTIVE, SIGVERSION_WITNESS_V0, false},
        {"witness version 6 with the minimal argument flag", ACTIVE | SCRIPT_VERIFY_MINIMALIF, SIGVERSION_WITNESS_V0, true},
        {"witness version 11", ACTIVE, SIGVERSION_WITNESS_V11, true},
    };

    Generator gen(0x636f6e646974696fULL);
    int succeeded = 0, unbalanced = 0, minimal = 0, deepest = 0;
    for (int n = 0; n < 4000; ++n) {
        const std::vector<Token> tokens = GenerateTokens(gen);
        const CScript script = ScriptOf(tokens);
        int depth = 0;
        for (const Token& t : tokens) {
            if (t.kind == TOKEN_IF || t.kind == TOKEN_NOTIF)
                deepest = std::max(deepest, ++depth);
            else if (t.kind == TOKEN_ENDIF && depth > 0)
                --depth;
        }
        for (const Mode& mode : modes) {
            const Outcome expected = Model(tokens, mode.minimalArgument);
            const Outcome got = Run(script, std::vector<valtype>(), mode.flags, mode.sigversion);
            BOOST_REQUIRE_MESSAGE(got.ok == expected.ok && got.error == expected.error && got.stack == expected.stack,
                "sequence " << n << " under " << mode.name << ", script " << HexStr(script.begin(), script.end())
                            << ": the loop gives " << Name(got.error) << " with " << got.stack.size()
                            << " items, the rule gives " << Name(expected.error) << " with " << expected.stack.size());
            if (expected.ok)
                ++succeeded;
            else if (expected.error == SCRIPT_ERR_UNBALANCED_CONDITIONAL)
                ++unbalanced;
            else if (expected.error == SCRIPT_ERR_MINIMALIF)
                ++minimal;
        }
    }
    BOOST_TEST_MESSAGE(succeeded << " succeeded, " << unbalanced << " unbalanced, " << minimal << " refused arguments, deepest nesting " << deepest);
    // The generated set holds each kind of sequence in number.
    BOOST_CHECK_MESSAGE(succeeded > 1000 && unbalanced > 1000 && minimal > 500 && deepest >= 10,
        succeeded << " succeeded, " << unbalanced << " unbalanced, " << minimal << " refused arguments, deepest nesting " << deepest);
}

// The written cases of nesting: each transition of OP_ELSE, a conditional
// opened in a branch that is not taken, the four unbalanced forms, and the
// deepest nesting a script of 10,000 bytes holds, through VerifyScript as a
// spend of each version.
BOOST_AUTO_TEST_CASE(the_written_cases_of_nesting)
{
    const valtype a(1, 0x0a), b(1, 0x0b), c(1, 0x0c), d(1, 0x0d);
    typedef std::vector<valtype> Stack;
    struct Case {
        const char* what;
        CScript script;
        bool ok;
        ScriptError error;
        Stack stack;
    };
    const Case cases[] = {
        {"the branch taken", CScript() << OP_1 << OP_IF << a << OP_ELSE << b << OP_ENDIF, true, SCRIPT_ERR_OK, {a}},
        {"the branch not taken", CScript() << OP_0 << OP_IF << a << OP_ELSE << b << OP_ENDIF, true, SCRIPT_ERR_OK, {b}},
        {"OP_NOTIF on a false argument", CScript() << OP_0 << OP_NOTIF << a << OP_ELSE << b << OP_ENDIF, true, SCRIPT_ERR_OK, {a}},
        {"a second OP_ELSE starts execution again", CScript() << OP_1 << OP_IF << a << OP_ELSE << b << OP_ELSE << c << OP_ENDIF, true, SCRIPT_ERR_OK, {a, c}},
        {"three OP_ELSE on a branch not taken", CScript() << OP_0 << OP_IF << a << OP_ELSE << b << OP_ELSE << c << OP_ELSE << d << OP_ENDIF, true, SCRIPT_ERR_OK, {b, d}},
        {"a conditional inside a branch not taken does not run, and its OP_ELSE starts nothing",
         CScript() << OP_0 << OP_IF << OP_1 << OP_IF << a << OP_ELSE << b << OP_ENDIF << OP_ELSE << c << OP_ENDIF, true, SCRIPT_ERR_OK, {c}},
        {"two levels, the inner false closed first",
         CScript() << OP_1 << OP_IF << OP_0 << OP_IF << a << OP_ENDIF << b << OP_ENDIF << c, true, SCRIPT_ERR_OK, {b, c}},
        {"a conditional opened and closed inside a branch not taken",
         CScript() << OP_0 << OP_IF << OP_1 << OP_IF << a << OP_ENDIF << b << OP_ENDIF << c, true, SCRIPT_ERR_OK, {c}},
        {"an inner OP_ELSE under a false outer, then the outer OP_ELSE",
         CScript() << OP_0 << OP_IF << OP_0 << OP_IF << a << OP_ELSE << b << OP_ENDIF << OP_ELSE << OP_0 << OP_IF << c << OP_ELSE << d << OP_ENDIF << OP_ENDIF,
         true, SCRIPT_ERR_OK, {d}},
        {"OP_ELSE with nothing open", CScript() << a << OP_ELSE, false, SCRIPT_ERR_UNBALANCED_CONDITIONAL, {a}},
        {"OP_ENDIF with nothing open", CScript() << a << OP_ENDIF, false, SCRIPT_ERR_UNBALANCED_CONDITIONAL, {a}},
        {"a conditional left open", CScript() << a << OP_1 << OP_IF, false, SCRIPT_ERR_UNBALANCED_CONDITIONAL, {a}},
        {"one OP_ENDIF too many", CScript() << a << OP_1 << OP_IF << OP_ENDIF << OP_ENDIF, false, SCRIPT_ERR_UNBALANCED_CONDITIONAL, {a}},
        {"OP_IF on an empty stack", CScript() << OP_IF << OP_ENDIF, false, SCRIPT_ERR_UNBALANCED_CONDITIONAL, {}},
        {"OP_IF on an empty stack inside a branch not taken reads nothing", CScript() << OP_0 << OP_IF << OP_IF << OP_ENDIF << OP_ENDIF << a, true, SCRIPT_ERR_OK, {a}},
    };
    for (const Case& t : cases) {
        for (SigVersion sigversion : {SIGVERSION_WITNESS_V0, SIGVERSION_WITNESS_V11}) {
            const Outcome got = Run(t.script, Stack(), ACTIVE, sigversion);
            BOOST_CHECK_MESSAGE(got.ok == t.ok && got.error == t.error && got.stack == t.stack,
                t.what << ": got " << Name(got.error) << " with " << got.stack.size() << " items");
        }
    }

    // The deepest nesting: 3,333 conditionals in 10,000 bytes.
    const int depth = 3333;
    auto nested = [&](opcodetype outermost, opcodetype inner) {
        CScript s;
        s << outermost << OP_IF;
        for (int i = 1; i < depth; ++i)
            s << inner << OP_IF;
        for (int i = 0; i < depth; ++i)
            s << OP_ENDIF;
        s << OP_1;
        BOOST_REQUIRE_EQUAL(s.size(), 10000u);
        return s;
    };
    // Every level true; every level false; the outermost false over true
    // arguments that are never read; the outermost true over one false level.
    for (const CScript& script : {nested(OP_1, OP_1), nested(OP_0, OP_0), nested(OP_0, OP_1), nested(OP_1, OP_0)}) {
        BOOST_CHECK_EQUAL(V6Verdict(script), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(V11Verdict(script), SCRIPT_ERR_OK);
    }
    // The same nesting with a marker inside the innermost level and an
    // OP_ELSE at each level on the way out: which markers are left says which
    // levels ran.
    {
        CScript s;
        for (int i = 0; i < 1000; ++i)
            s << OP_1 << OP_IF;
        s << a;
        for (int i = 0; i < 1000; ++i)
            s << OP_ELSE << b << OP_ENDIF;
        const Outcome got = Run(s, Stack(), ACTIVE, SIGVERSION_WITNESS_V0);
        BOOST_CHECK(got.ok);
        BOOST_CHECK(got.stack == Stack(1, a));
    }
    {
        // The outermost level false: its OP_ELSE, the last one, is the only
        // one that starts execution.
        CScript s;
        s << OP_0 << OP_IF;
        for (int i = 1; i < 1000; ++i)
            s << OP_1 << OP_IF;
        s << a;
        for (int i = 0; i < 1000; ++i)
            s << OP_ELSE << b << OP_ENDIF;
        const Outcome got = Run(s, Stack(), ACTIVE, SIGVERSION_WITNESS_V11);
        BOOST_CHECK(got.ok);
        BOOST_CHECK(got.stack == Stack(1, b));
    }
}

// The template hash a checker compares against is the written format, for
// every input of generated transactions with a scriptSig on none, all, the
// first, the last and some of their inputs, whether the checker is built with
// the transaction's precomputed data or without it, and through the opcode.
BOOST_AUTO_TEST_CASE(the_template_hash_is_the_written_format_with_and_without_the_precomputed_data)
{
    Generator gen(0x74656d706c617465ULL);
    int checked = 0, withScriptSig = 0;
    for (int n = 0; n < 400; ++n) {
        const ScriptSigPattern pattern = static_cast<ScriptSigPattern>(n % SCRIPTSIG_PATTERNS);
        const CTransaction tx(GenerateTx(gen, pattern));
        const PrecomputedTransactionData txdata(tx);
        bool any = false;
        for (const CTxIn& in : tx.vin)
            any = any || !in.scriptSig.empty();
        withScriptSig += any ? 1 : 0;

        for (uint32_t i = 0; i < tx.vin.size(); ++i) {
            const valtype right = TemplateHash(tx, i);
            valtype wrong = right;
            const size_t byte = gen.Below(32);
            const int bit = static_cast<int>(gen.Below(8));
            wrong[byte] ^= static_cast<unsigned char>(1 << bit);

            const TransactionSignatureChecker without(&tx, i, AMOUNT);
            const TransactionSignatureChecker with(&tx, i, AMOUNT, txdata);
            for (const TransactionSignatureChecker* checker : {&without, &with}) {
                BOOST_REQUIRE_MESSAGE(checker->CheckTemplateVerify(right),
                    "transaction " << n << ", input " << i << ": the written format is not the hash the checker "
                                   << (checker == &with ? "with" : "without") << " the precomputed data compares against");
                BOOST_CHECK(!checker->CheckTemplateVerify(wrong));
                // The hash of another input of the same transaction.
                if (tx.vin.size() > 1)
                    BOOST_CHECK(!checker->CheckTemplateVerify(TemplateHash(tx, (i + 1) % tx.vin.size())));

                const Outcome ok = Run(CScript() << right << OP_CHECKTEMPLATEVERIFY, std::vector<valtype>(), ACTIVE, SIGVERSION_WITNESS_V0, *checker);
                BOOST_CHECK(ok.ok && ok.stack == std::vector<valtype>(1, right));
                const Outcome bad = Run(CScript() << wrong << OP_CHECKTEMPLATEVERIFY, std::vector<valtype>(), ACTIVE, SIGVERSION_WITNESS_V11, *checker);
                BOOST_CHECK(!bad.ok && bad.error == SCRIPT_ERR_CHECKTEMPLATEVERIFY);
            }
            ++checked;
        }
    }
    BOOST_CHECK(checked > 1000);
    BOOST_CHECK_MESSAGE(withScriptSig > 200 && withScriptSig < 400, withScriptSig << " of 400 transactions carry a scriptSig");

    // One scriptSig changes the hash of every input, and so does its place.
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(3);
    mtx.vout.push_back(CTxOut(COIN, CScript() << OP_1 << valtype(32, 0x22)));
    const CTransaction none(mtx);
    mtx.vin[0].scriptSig = CScript() << OP_1;
    const CTransaction first(mtx);
    mtx.vin[0].scriptSig = CScript();
    mtx.vin[2].scriptSig = CScript() << OP_1;
    const CTransaction last(mtx);
    for (uint32_t i = 0; i < 3; ++i) {
        BOOST_CHECK(TemplateHash(none, i) != TemplateHash(first, i));
        BOOST_CHECK(TemplateHash(first, i) != TemplateHash(last, i));
        BOOST_CHECK(TransactionSignatureChecker(&first, i, AMOUNT).CheckTemplateVerify(TemplateHash(first, i)));
        BOOST_CHECK(!TransactionSignatureChecker(&first, i, AMOUNT).CheckTemplateVerify(TemplateHash(none, i)));
        BOOST_CHECK(!TransactionSignatureChecker(&last, i, AMOUNT).CheckTemplateVerify(TemplateHash(first, i)));
    }
}

// The precomputed data of a transaction holds the three parts of the template
// hash that are the same for every input: whether a scriptSig is present, and
// the hashes of the scriptSigs, the sequences and the outputs, as the format
// writes them. Without a scriptSig the first hash is 32 zero bytes.
BOOST_AUTO_TEST_CASE(the_precomputed_data_holds_the_three_parts_of_the_template)
{
    Generator gen(0x7061727473ULL);
    int with = 0, without = 0;
    for (int n = 0; n < 400; ++n) {
        const CTransaction tx(GenerateTx(gen, static_cast<ScriptSigPattern>(n % SCRIPTSIG_PATTERNS)));
        const PrecomputedTransactionData txdata(tx);
        const TemplateHashParts& parts = txdata.templateParts;
        const bool any = AnyScriptSig(tx);
        (any ? with : without) += 1;
        BOOST_REQUIRE_EQUAL(parts.fHasScriptSigs, any);
        BOOST_CHECK(valtype(parts.scriptSigs, parts.scriptSigs + 32) == (any ? ScriptSigsPart(tx) : valtype(32, 0x00)));
        BOOST_CHECK(valtype(parts.sequences, parts.sequences + 32) == SequencesPart(tx));
        BOOST_CHECK(valtype(parts.outputs, parts.outputs + 32) == OutputsPart(tx));

        // Built on its own, as a checker without the data builds it.
        const TemplateHashParts alone(tx);
        BOOST_CHECK_EQUAL(alone.fHasScriptSigs, parts.fHasScriptSigs);
        BOOST_CHECK(memcmp(alone.scriptSigs, parts.scriptSigs, 32) == 0);
        BOOST_CHECK(memcmp(alone.sequences, parts.sequences, 32) == 0);
        BOOST_CHECK(memcmp(alone.outputs, parts.outputs, 32) == 0);
    }
    // One pattern in five carries no scriptSig.
    BOOST_CHECK_MESSAGE(with > 250 && without >= 80, with << " transactions with a scriptSig and " << without << " without");

    // A transaction with no input and no output: each hash is that of no
    // bytes.
    const CTransaction empty{CMutableTransaction()};
    const TemplateHashParts none(empty);
    const valtype nothing = Sha256(valtype());
    BOOST_CHECK(!none.fHasScriptSigs);
    BOOST_CHECK(valtype(none.sequences, none.sequences + 32) == nothing);
    BOOST_CHECK(valtype(none.outputs, none.outputs + 32) == nothing);

    // A scriptSig on an input that is not the one checked, and of a kind no
    // script evaluates, is part of the template of every input: a coinbase
    // input beside two others.
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(3);
    mtx.vin[1].scriptSig = CScript() << 500 << valtype(40, 0x33);
    mtx.vout.push_back(CTxOut(COIN, CScript() << OP_1 << valtype(32, 0x22)));
    const CTransaction carrying(mtx);
    const PrecomputedTransactionData carryingData(carrying);
    BOOST_CHECK(carryingData.templateParts.fHasScriptSigs);
    for (uint32_t i = 0; i < 3; ++i)
        BOOST_CHECK(TransactionSignatureChecker(&carrying, i, AMOUNT, carryingData).CheckTemplateVerify(TemplateHash(carrying, i)));
}

// A checker that holds the precomputed data takes the scriptSigs, the
// sequences and the outputs of the template from it and reads none of them
// from its transaction. The case shows it by giving a checker over one
// transaction the data of another, which no caller does: the two agree on the
// fields the checker reads from the transaction (the version, the lock time
// and the two counts) and differ in every scriptSig, sequence and output. The
// hash the checker accepts is the one the data gives. A checker without the
// data accepts the hash of its own transaction.
BOOST_AUTO_TEST_CASE(a_checker_that_holds_the_precomputed_data_reads_no_script_of_its_transaction)
{
    CMutableTransaction a;
    a.nVersion = 2;
    a.nLockTime = 700000;
    a.vin.resize(3);
    for (size_t i = 0; i < 3; ++i) {
        a.vin[i].prevout = COutPoint(uint256S("0x1111111111111111111111111111111111111111111111111111111111111111"), static_cast<uint32_t>(i));
        a.vin[i].nSequence = 10 + static_cast<uint32_t>(i);
    }
    a.vin[2].scriptSig = CScript() << valtype(20, 0x61);
    a.vout.push_back(CTxOut(3 * COIN, CScript() << OP_1 << valtype(32, 0x0a)));
    a.vout.push_back(CTxOut(4 * COIN, CScript() << OP_1 << valtype(32, 0x1a)));

    // The same version, lock time, number of inputs and number of outputs.
    CMutableTransaction b = a;
    for (size_t i = 0; i < 3; ++i)
        b.vin[i].nSequence = 900 + static_cast<uint32_t>(i);
    b.vin[2].scriptSig = CScript();
    b.vin[0].scriptSig = CScript() << valtype(33, 0x62);
    b.vout[0] = CTxOut(5 * COIN, CScript() << OP_1 << valtype(32, 0x0b));
    b.vout[1] = CTxOut(6 * COIN, CScript() << OP_6 << valtype(32, 0x1b));

    const CTransaction txA(a), txB(b);
    const PrecomputedTransactionData dataA(txA), dataB(txB);
    for (uint32_t i = 0; i < 3; ++i) {
        const valtype hashA = TemplateHash(txA, i);
        const valtype hashB = TemplateHash(txB, i);
        BOOST_REQUIRE(hashA != hashB);

        // The pairing every caller makes.
        BOOST_CHECK(TransactionSignatureChecker(&txA, i, AMOUNT, dataA).CheckTemplateVerify(hashA));
        BOOST_CHECK(TransactionSignatureChecker(&txB, i, AMOUNT, dataB).CheckTemplateVerify(hashB));
        BOOST_CHECK(TransactionSignatureChecker(&txB, i, AMOUNT).CheckTemplateVerify(hashB));
        BOOST_CHECK(!TransactionSignatureChecker(&txB, i, AMOUNT).CheckTemplateVerify(hashA));

        // A checker over B that holds the data of A.
        const TransactionSignatureChecker crossed(&txB, i, AMOUNT, dataA);
        BOOST_CHECK_MESSAGE(crossed.CheckTemplateVerify(hashA),
            "input " << i << ": a checker that holds the precomputed data hashed a script, a sequence or an output of its transaction");
        BOOST_CHECK(!crossed.CheckTemplateVerify(hashB));
    }
}

// A digest for each of three families of generated scripts: what EvalScript
// returns, its error and the stack it leaves, for every script of the family.
// The three values were computed on the loop as it stood at the merge of
// witness version 11. A change that alters no verdict and no stack leaves them
// where they are, and one that means to alter some moves the family it
// touches and says so by its new value.
BOOST_AUTO_TEST_CASE(the_three_families_keep_their_digests)
{
    struct Mode {
        unsigned int flags;
        SigVersion sigversion;
    };
    const Mode modes[] = {
        {SCRIPT_VERIFY_SCRIPT_RESTORE, SIGVERSION_BASE},
        {ACTIVE, SIGVERSION_WITNESS_V0},
        {ACTIVE | SCRIPT_VERIFY_MINIMALIF | SCRIPT_VERIFY_MINIMALDATA, SIGVERSION_WITNESS_V0},
        {ACTIVE, SIGVERSION_WITNESS_V11},
        {SCRIPT_VERIFY_NONE, SIGVERSION_BASE},
    };

    // The numbers: the three arithmetic opcodes over every pair of the
    // operands above and over generated pairs, items that are not minimal
    // numbers or are over eight bytes, the length OP_SIZE pushes, and the
    // sixteen small numbers.
    CSHA256 numbers;
    size_t numberRuns = 0, numberOk = 0;
    {
        const opcodetype arithmetic[] = {OP_MUL, OP_DIV, OP_MOD};
        const std::vector<int64_t> operands = Operands();
        std::vector<std::pair<valtype, valtype> > pairs;
        for (int64_t x : operands)
            for (int64_t y : operands)
                pairs.push_back(std::make_pair(NumberEncoding(x), NumberEncoding(y)));
        Generator gen(0x61726974686d65ULL);
        for (int i = 0; i < 20000; ++i) {
            const int wx = 1 + static_cast<int>(gen.Below(63));
            const int wy = 1 + static_cast<int>(gen.Below(63));
            int64_t x = static_cast<int64_t>(gen.Next() & ((uint64_t(1) << wx) - 1));
            int64_t y = static_cast<int64_t>(gen.Next() & ((uint64_t(1) << wy) - 1));
            if (gen.Below(2))
                x = -x;
            if (gen.Below(2))
                y = -y;
            pairs.push_back(std::make_pair(NumberEncoding(x), NumberEncoding(y)));
        }
        // Items that are not the encoding of a number of eight bytes.
        const char* const odd[] = {"80", "00", "0100", "0080", "ffffffffffffffff", "ffffffffffffffff00",
                                   "000000000000008080", "010000000000000000", "0000000000000080"};
        for (const char* x : odd)
            for (const char* y : odd)
                pairs.push_back(std::make_pair(ParseHex(x), ParseHex(y)));
        for (const char* x : odd) {
            pairs.push_back(std::make_pair(ParseHex(x), NumberEncoding(3)));
            pairs.push_back(std::make_pair(NumberEncoding(-3), ParseHex(x)));
        }
        for (const std::pair<valtype, valtype>& p : pairs) {
            for (opcodetype op : arithmetic) {
                for (const Mode& mode : modes) {
                    Record(numbers, Run(CScript() << op, {p.first, p.second}, mode.flags, mode.sigversion), numberOk);
                    ++numberRuns;
                }
            }
        }
        const size_t lengths[] = {0, 1, 2, 75, 76, 127, 128, 255, 256, 520, 2421};
        for (size_t length : lengths) {
            for (const Mode& mode : modes) {
                Record(numbers, Run(CScript() << OP_SIZE, {valtype(length, 0x5a)}, mode.flags, mode.sigversion), numberOk);
                ++numberRuns;
            }
        }
        for (int n = 1; n <= 16; ++n) {
            for (const Mode& mode : modes) {
                Record(numbers, Run(CScript() << static_cast<opcodetype>(OP_1 + n - 1), std::vector<valtype>(), mode.flags, mode.sigversion), numberOk);
                ++numberRuns;
            }
        }
    }

    // The conditionals: generated sequences as in the case above, from
    // another seed, and each of them a second time with a first item on the
    // stack that a branch with no argument of its own reads.
    CSHA256 conditionals;
    size_t conditionalRuns = 0, conditionalOk = 0;
    {
        Generator gen(0x6e657374696e67ULL);
        for (int n = 0; n < 6000; ++n) {
            const CScript script = ScriptOf(GenerateTokens(gen));
            const valtype first = ParseHex(ARGUMENTS[gen.Below(sizeof(ARGUMENTS) / sizeof(ARGUMENTS[0]))]);
            for (const Mode& mode : modes) {
                Record(conditionals, Run(script, std::vector<valtype>(), mode.flags, mode.sigversion), conditionalOk);
                Record(conditionals, Run(script, {first}, mode.flags, mode.sigversion), conditionalOk);
                conditionalRuns += 2;
            }
        }
    }

    // The template checks: for every input of generated transactions, the
    // hash of the written format and two that differ from it, through the
    // opcode, with a checker that holds the precomputed data and one that
    // does not. The hash itself goes into the digest.
    CSHA256 templates;
    size_t templateRuns = 0, templateOk = 0;
    {
        Generator gen(0x636f76656e616e74ULL);
        for (int n = 0; n < 300; ++n) {
            const CTransaction tx(GenerateTx(gen, static_cast<ScriptSigPattern>(n % SCRIPTSIG_PATTERNS)));
            const PrecomputedTransactionData txdata(tx);
            for (uint32_t i = 0; i < tx.vin.size(); ++i) {
                const valtype right = TemplateHash(tx, i);
                valtype wrong = right;
                wrong[31] ^= 0x01;
                templates.Write(right.data(), right.size());
                const TransactionSignatureChecker without(&tx, i, AMOUNT);
                const TransactionSignatureChecker with(&tx, i, AMOUNT, txdata);
                for (const TransactionSignatureChecker* checker : {&without, &with}) {
                    for (const Mode& mode : modes) {
                        Record(templates, Run(CScript() << right << OP_CHECKTEMPLATEVERIFY, std::vector<valtype>(), mode.flags, mode.sigversion, *checker), templateOk);
                        Record(templates, Run(CScript() << wrong << OP_CHECKTEMPLATEVERIFY << OP_CHECKTEMPLATEVERIFY, std::vector<valtype>(), mode.flags, mode.sigversion, *checker), templateOk);
                        Record(templates, Run(CScript() << valtype(31, 0x01) << OP_CHECKTEMPLATEVERIFY, std::vector<valtype>(), mode.flags, mode.sigversion, *checker), templateOk);
                        templateRuns += 3;
                    }
                }
            }
        }
    }

    const std::string numbersDigest = Hex(numbers);
    const std::string conditionalsDigest = Hex(conditionals);
    const std::string templatesDigest = Hex(templates);
    BOOST_TEST_MESSAGE("numbers: " << numberRuns << " runs, " << numberOk << " succeeded, " << numbersDigest);
    BOOST_TEST_MESSAGE("conditionals: " << conditionalRuns << " runs, " << conditionalOk << " succeeded, " << conditionalsDigest);
    BOOST_TEST_MESSAGE("templates: " << templateRuns << " runs, " << templateOk << " succeeded, " << templatesDigest);

    BOOST_CHECK_EQUAL(numbersDigest, "16a0b39cd0fff9c64d1cb07c2ec77a6a56df83853d7eee8011cf39fdca9fbb55");
    BOOST_CHECK_EQUAL(conditionalsDigest, "2786a8b84efc82a19be50826b6dd94b0a32b4f5a627e2ddd22e5a90a0ab18c58");
    BOOST_CHECK_EQUAL(templatesDigest, "ed007c65d27ca989e653be3465d945770e4bb69b212013d473f17c199a6f9958");
}

BOOST_AUTO_TEST_SUITE_END()
