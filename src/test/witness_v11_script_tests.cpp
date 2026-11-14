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
// Three places pass an input without evaluating it, and a fourth passes one
// check: the dormant version, a committed item of a sub-version this release
// does not define, a script that holds a reserved byte, and a key-hash check
// on a key of a type this release does not define. Each succeeds with a
// block's flags and is refused under
// SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, which relay sets and no
// block does.
//
// The bytes of the format (the version number 11, the sub-version 0xc0, the
// key type 0x00, the lengths and the figures) are written out here and not
// read from script/script.h, so that a constant changed there fails a test
// here.

#include "amount.h"
#include "crypto/sha256.h"
#include "hash.h"
#include "key.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "utilstrencodings.h"

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

//! A block's flags with the three deployments active.
const unsigned int ACTIVE = BLOCK | SCRIPT_VERIFY_CTV | SCRIPT_VERIFY_APO | SCRIPT_VERIFY_CSFS;

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

//! A signature over `hash`, with no hash type byte.
valtype SignHash(const CKey& key, const uint256& hash)
{
    valtype sig;
    BOOST_REQUIRE(key.Sign(hash, sig));
    BOOST_REQUIRE_EQUAL(sig.size(), 2420u);
    return sig;
}

//! A signature item over the message witness version 6 signs for `script`.
valtype SignV6Message(const CKey& key, const CScript& script, const CTransaction& tx, int hashType)
{
    valtype sig = SignHash(key, SignatureHash(script, tx, 0, hashType, AMOUNT, SIGVERSION_WITNESS_V0, nullptr));
    sig.push_back(static_cast<unsigned char>(hashType));
    return sig;
}

//! The message a signature of witness version 11 signs, written out from the
//! format: the preimage of witness version 6's standard hash types, then the
//! bytes 0x0b, 0xc0 and the type byte of the key.
uint256 V11Message(const CScript& script, const CTransaction& tx, unsigned int nIn, int hashType,
                   const CAmount& amount, unsigned char keyType)
{
    const bool anyoneCanPay = (hashType & 0x80) != 0;
    const int base = hashType & 0x1f;
    uint256 hashPrevouts, hashSequence, hashOutputs;
    if (!anyoneCanPay) {
        CHashWriter ss(SER_GETHASH, 0);
        for (const CTxIn& in : tx.vin)
            ss << in.prevout;
        hashPrevouts = ss.GetHash();
    }
    if (!anyoneCanPay && base != SIGHASH_SINGLE && base != SIGHASH_NONE) {
        CHashWriter ss(SER_GETHASH, 0);
        for (const CTxIn& in : tx.vin)
            ss << in.nSequence;
        hashSequence = ss.GetHash();
    }
    if (base != SIGHASH_SINGLE && base != SIGHASH_NONE) {
        CHashWriter ss(SER_GETHASH, 0);
        for (const CTxOut& out : tx.vout)
            ss << out;
        hashOutputs = ss.GetHash();
    } else if (base == SIGHASH_SINGLE) {
        BOOST_REQUIRE(nIn < tx.vout.size());
        CHashWriter ss(SER_GETHASH, 0);
        ss << tx.vout[nIn];
        hashOutputs = ss.GetHash();
    }
    CHashWriter ss(SER_GETHASH, 0);
    ss << tx.nVersion << hashPrevouts << hashSequence << tx.vin[nIn].prevout;
    ss << static_cast<const CScriptBase&>(script);
    ss << amount << tx.vin[nIn].nSequence << hashOutputs << tx.nLockTime << hashType;
    ss << static_cast<unsigned char>(0x0b) << static_cast<unsigned char>(0xc0) << keyType;
    return ss.GetHash();
}

//! A signature item of witness version 11 for input `nIn`.
valtype SignV11(const CKey& key, const CScript& script, const CTransaction& tx, int hashType = SIGHASH_ALL,
                unsigned int nIn = 0, unsigned char keyType = 0x00)
{
    valtype sig = SignHash(key, V11Message(script, tx, nIn, hashType, AMOUNT, keyType));
    sig.push_back(static_cast<unsigned char>(hashType));
    return sig;
}

ScriptError Verdict(const CScript& output, const std::vector<valtype>& witness, unsigned int flags,
                    const CTransaction& tx, unsigned int nIn = 0, const CScript& scriptSig = CScript())
{
    CScriptWitness w;
    w.stack = witness;
    ScriptError serr = SCRIPT_ERR_OK;
    TransactionSignatureChecker checker(&tx, nIn, AMOUNT);
    const bool ok = VerifyScript(scriptSig, output, &w, flags, checker, &serr);
    BOOST_CHECK_MESSAGE(ok == (serr == SCRIPT_ERR_OK),
        "VerifyScript returned " << ok << " with the error " << ScriptErrorString(serr));
    return serr;
}

std::string Name(ScriptError e) { return std::string(ScriptErrorString(e)); }

//! An output of witness version 11 and a witness that spends it.
struct Spend {
    CScript output;
    std::vector<valtype> witness;
};

//! The spend of `script` with the given satisfaction items.
Spend SpendOf(const CScript& script, const std::vector<valtype>& satisfaction = std::vector<valtype>(),
              unsigned char subversion = 0xc0, const valtype& trailer = TRAILER)
{
    Spend s;
    const valtype committed = CommittedItem(script, subversion);
    s.output = OutputFor(committed);
    s.witness = satisfaction;
    s.witness.push_back(committed);
    s.witness.push_back(trailer);
    return s;
}

ScriptError Verdict(const Spend& s, unsigned int flags, const CTransaction& tx)
{
    return Verdict(s.output, s.witness, flags, tx);
}

size_t SigOps(const Spend& s, unsigned int flags)
{
    CScriptWitness w;
    w.stack = s.witness;
    return CountWitnessSigOps(CScript(), s.output, &w, flags);
}

//! A script of exactly `size` bytes that leaves one true item: pushes that are
//! dropped, then OP_1.
CScript ScriptOfSize(size_t size)
{
    BOOST_REQUIRE(size >= 4);
    CScript s;
    size_t rest = size - 1;
    if (rest % 2 == 1) {
        s << valtype(1, 0xaa) << OP_DROP;  // three bytes
        rest -= 3;
    }
    for (size_t i = 0; i < rest / 2; ++i)
        s << OP_1 << OP_DROP;
    s << OP_1;
    BOOST_REQUIRE_EQUAL(s.size(), size);
    return s;
}

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
        BOOST_REQUIRE_EQUAL(ownerItem.size(), 1313u);
        script = SingleKeyScript(ownerItem);
        committed = CommittedItem(script);
        output = OutputFor(committed);

        // One item, the byte every input's last witness item begins with.
        nothing = {TRAILER};
        // The committed item, which the spender reads from the output's
        // funding, and no satisfaction item.
        noSatisfaction = {committed, TRAILER};
        // The stranger's own key and a signature made with it over the
        // version's message: valid for that key, so only the key-hash
        // comparison stands between it and the output.
        strangersKey = {SignV11(stranger, script, tx), strangerItem, committed, TRAILER};
        // The owner's key item, which is public once the owner has spent, and
        // a signature the owner made over the message of witness version 6.
        ownersKeyV6Message = {SignV6Message(owner, script, tx, SIGHASH_ALL), ownerItem, committed, TRAILER};
    }
};

// ---------------------------------------------------------------------------
// The class of each byte, transcribed from the rule: the pushes and the
// opcodes below are defined; 0xb3 and 0xb4 are defined while their deployment
// is active and reserved while it is not; 0xbb to 0xef are reserved; every
// other byte is refused, the seven asset and attestation opcodes with
// SCRIPT_ERR_BAD_OPCODE and the rest with SCRIPT_ERR_DISALLOWED_OPCODE.
// ---------------------------------------------------------------------------
const opcodetype DEFINED[] = {
    OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF,
    OP_DROP, OP_SIZE, OP_EQUAL, OP_EQUALVERIFY, OP_SHA256,
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY,
    OP_CHECKDILITHIUMKEYHASH,
    OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT,
    OP_AND, OP_OR, OP_XOR, OP_MUL, OP_DIV, OP_MOD,
};

const opcodetype ASSET[] = {
    OP_USDSOQ_MINT, OP_USDSOQ_BURN, OP_USDSOQ_FREEZE, OP_USDSOQ_ROTATE,
    OP_SOQUOBSCURA_RANGEPROOF, OP_CHECKFOLDPROOF, OP_CHECKPATAGG,
};

enum ByteClass { CLASS_PUSH, CLASS_DEFINED, CLASS_RESERVED, CLASS_REFUSED_BAD_OPCODE, CLASS_REFUSED_DISALLOWED };

ByteClass ExpectedClass(int b, unsigned int flags)
{
    if (b <= 0x4e || (b >= 0x51 && b <= 0x60))
        return CLASS_PUSH;
    for (opcodetype op : DEFINED)
        if (op == b)
            return CLASS_DEFINED;
    if (b == 0xb3)
        return (flags & SCRIPT_VERIFY_CTV) ? CLASS_DEFINED : CLASS_RESERVED;
    if (b == 0xb4)
        return (flags & SCRIPT_VERIFY_CSFS) ? CLASS_DEFINED : CLASS_RESERVED;
    if (b >= 0xbb && b <= 0xef)
        return CLASS_RESERVED;
    for (opcodetype op : ASSET)
        if (op == b)
            return CLASS_REFUSED_BAD_OPCODE;
    return CLASS_REFUSED_DISALLOWED;
}

//! The bytes of one push whose opcode byte is `b`.
valtype PushBytes(int b)
{
    valtype raw(1, static_cast<unsigned char>(b));
    if (b >= 0x01 && b <= 0x4b) {
        raw.insert(raw.end(), static_cast<size_t>(b), 0x01);
    } else if (b == 0x4c) {
        raw.push_back(1);
        raw.push_back(0xaa);
    } else if (b == 0x4d) {
        raw.push_back(1);
        raw.push_back(0);
        raw.push_back(0xaa);
    } else if (b == 0x4e) {
        raw.push_back(1);
        raw.insert(raw.end(), 3, 0);
        raw.push_back(0xaa);
    }
    return raw;
}

CScript Raw(const valtype& bytes) { return CScript(bytes.begin(), bytes.end()); }

//! The fixed transaction, input index, amount and script of the message vectors.
CMutableTransaction VectorTx()
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 500;
    CTxIn a;
    a.prevout = COutPoint(uint256S("0x1111111111111111111111111111111111111111111111111111111111111111"), 0);
    a.nSequence = 0xfffffffe;
    CTxIn b;
    b.prevout = COutPoint(uint256S("0x3333333333333333333333333333333333333333333333333333333333333333"), 7);
    b.nSequence = 0xfffffffd;
    tx.vin.push_back(a);
    tx.vin.push_back(b);
    tx.vout.push_back(CTxOut(1234567890, CScript() << OP_1 << valtype(32, 0x22)));
    tx.vout.push_back(CTxOut(987654321, CScript() << OP_11 << valtype(32, 0x44)));
    return tx;
}

//! The template hash OP_CHECKTEMPLATEVERIFY compares, written out from its
//! fields for a transaction whose scriptSigs are empty: the version, the lock
//! time, the number of inputs, the hash of the sequences, the number of
//! outputs, the hash of the outputs and the input's index.
valtype TemplateHash(const CTransaction& tx, uint32_t nIn)
{
    auto le32 = [](CSHA256& h, uint32_t v) {
        const unsigned char b[4] = {(unsigned char)v, (unsigned char)(v >> 8), (unsigned char)(v >> 16), (unsigned char)(v >> 24)};
        h.Write(b, 4);
    };
    auto le64 = [](CSHA256& h, uint64_t v) {
        unsigned char b[8];
        for (int i = 0; i < 8; ++i)
            b[i] = (unsigned char)(v >> (8 * i));
        h.Write(b, 8);
    };
    CSHA256 sequences;
    for (const CTxIn& in : tx.vin) {
        BOOST_REQUIRE(in.scriptSig.empty());
        le32(sequences, in.nSequence);
    }
    unsigned char sequencesHash[32];
    sequences.Finalize(sequencesHash);
    CSHA256 outputs;
    for (const CTxOut& out : tx.vout) {
        le64(outputs, (uint64_t)out.nValue);
        le32(outputs, (uint32_t)out.scriptPubKey.size());
        outputs.Write(out.scriptPubKey.data(), out.scriptPubKey.size());
    }
    unsigned char outputsHash[32];
    outputs.Finalize(outputsHash);

    CSHA256 h;
    le32(h, (uint32_t)tx.nVersion);
    le32(h, tx.nLockTime);
    le32(h, (uint32_t)tx.vin.size());
    h.Write(sequencesHash, 32);
    le32(h, (uint32_t)tx.vout.size());
    h.Write(outputsHash, 32);
    le32(h, nIn);
    valtype result(32);
    h.Finalize(result.data());
    return result;
}

//! A checker that counts how many times it computes the template hash.
struct CountingChecker : public TransactionSignatureChecker {
    mutable int computations;
    CountingChecker(const CTransaction* tx, unsigned int nIn) : TransactionSignatureChecker(tx, nIn, AMOUNT), computations(0) {}
    void ComputeTemplateHash(unsigned char* hashOut) const override
    {
        ++computations;
        TransactionSignatureChecker::ComputeTemplateHash(hashOut);
    }
};

const unsigned int VECTOR_INPUT = 1;
const CAmount VECTOR_AMOUNT = 5000000000LL;

CScript VectorScript()
{
    return CScript() << valtype(32, 0x55) << OP_CHECKDILITHIUMKEYHASH << OP_1;
}

std::string RawHex(const uint256& h) { return HexStr(h.begin(), h.end()); }

//! The message of witness version 11 for the fixed transaction above and the
//! key type 0x00, one a hash type the version admits. Computed from the written
//! format by a program that shares no code with the node.
struct MessageVector {
    int hashType;
    const char* message;
};
const MessageVector MESSAGE_VECTORS[] = {
    {0x01, "a683c2a085bac288f36216a4fd84b2a5d8e05ba66ec463319bf15d3d56091f72"},
    {0x02, "b7d50b02a69e9cd0c16b6a39f3ba3bbc2a5e1d49c45ce8928dd35f0a65ef45d1"},
    {0x03, "5d630c203f2124d8bcf147d0da0306750120e80ad4f321f6262df6971a3a5d3c"},
    {0x81, "e6f0535b44ff4bef701a4878901b936b9b6863a490d350620be77eaddaa41a28"},
    {0x82, "d51c099fa57badd5eb1f159b0f7c2192d21fba6e56772b4a6567e421eba85eb8"},
    {0x83, "667885d93dc4c2649fca2639925d0c3a0e3433ef03dc9ea6dcac12d99a9e9ec8"},
};
//! The same for hash type 0x01 with the type byte 0x01 in place of 0x00.
const char* const MESSAGE_VECTOR_OTHER_KEY_TYPE = "ff428cfbd79152670ac676471c19b5810d8dcfb7b3c43739efd4b80ce35e7ded";

//! What SignatureHash returned for the fixed transaction and script above under
//! the two signature versions that existed before witness version 11, at input
//! 1 with the transaction's two outputs and with its second output removed.
//! Printed by the function as it stood before SIGVERSION_WITNESS_V11 was added.
struct ExistingSighash {
    int outputs;
    int hashType;
    const char* witnessV0;
    const char* base;
};
const ExistingSighash EXISTING_SIGHASHES[] = {
    {2, 0x01, "dfebe931a97af143f2f2011766b307d3276ba03707594951e300334b9fcf2c91",
              "035e170c200a4e849c17ed897c12edc17a1dc9e388546f06fa4248310844b495"},
    {2, 0x02, "10e61336e5be336db58c55d0b6a110ba41b3f56ac242964f25bf03dfd984b7ef",
              "13bab9704ac0f85e86b7ed5a292a00615b8aec80149fbd1b97f1e2ee6e374117"},
    {2, 0x03, "b674221be7a6eefae218221f4adce5fd817381221ab55f5d0e8a8aaaf3a78541",
              "d9155f96c84a6d72654377da0d93c2eb591f0fde46ae460cdbc31c01f2ad5b28"},
    {2, 0x81, "1feeb1d18f4588963484dc44f4bd59bd4d6c2d65184ceefda8be1d533382e750",
              "dbabb833ff03b8569d9860414ec4081debec9f21fdcb841f5d1dd2791cfb7861"},
    {2, 0x82, "e9b832ca0a68b568eef53fbfc6839412bfd02e20f2ad16513f66b8f3c3331789",
              "d6db856b61d7ed85a4ace62820a3baab647f498f498f01b41f35796eb4ed0f2e"},
    {2, 0x83, "e2bad1c69d40ba61b7c3b967c8632792b9801f25151c336b552c03de5183f31e",
              "5a8b0d4375057948c02a2b185373544202e5700539f191af7865893c374bd48a"},
    {2, 0x41, "8035bb0264e221b5bd5141d2b4d3df5a7aaad3b9f1fb5104607b5cc180bd3746",
              "45512fedbc01c09a84efc5e1fa837f95cbcf3529234ff3399095af1a993d9b2a"},
    {2, 0x42, "6ea063c9a51d288e95ab9ee30245c333f2193c73a5b150e4afa035a86d81c093",
              "ab0c00fb3eff4c4a5793a94903fa8e2560b13c621b372eccc96e6fc82c230bf0"},
    {2, 0xc1, "0100000000000000000000000000000000000000000000000000000000000000",
              "ce05b0d778362780f01c49a2a999299ba98ad435a44e722667074fde94aa4dc1"},
    {2, 0xc2, "0100000000000000000000000000000000000000000000000000000000000000",
              "e2db30fb67275a2d0806a017037acca2d55174339d90264859a08cdc96435ebd"},
    {1, 0x01, "e34929c0fb6d0b086f4c888a1747f771b79f5fe797d140b65d6335d957b9b3da",
              "48b5c95b09a5e4628836cf56be1c4bb312a167dca042c32fd160adeb47b25615"},
    {1, 0x02, "10e61336e5be336db58c55d0b6a110ba41b3f56ac242964f25bf03dfd984b7ef",
              "13bab9704ac0f85e86b7ed5a292a00615b8aec80149fbd1b97f1e2ee6e374117"},
    {1, 0x03, "e950cec80147952655ab929bd516bc6b1fa5e001ef39cb7f2867919d44b59265",
              "0100000000000000000000000000000000000000000000000000000000000000"},
    {1, 0x81, "d64f01cc9f182b63bbec4afcef315fd29ba81a3fae28341fe054417f66687fd0",
              "624931576f67f359142e7a6149a840d6897cc270146f71cd3d1025554332d492"},
    {1, 0x82, "e9b832ca0a68b568eef53fbfc6839412bfd02e20f2ad16513f66b8f3c3331789",
              "d6db856b61d7ed85a4ace62820a3baab647f498f498f01b41f35796eb4ed0f2e"},
    {1, 0x83, "ee6f5baae6fee14f8d6183a9ebf19d3655dcd75736cd9cafa3952d64755bac03",
              "0100000000000000000000000000000000000000000000000000000000000000"},
    {1, 0x41, "887a2740a6442b74f0f983f94e01939c380785cd4b603309f766eb8e2fd9bff3",
              "b6ccdbcefd544f820fb8d48dc74e6ed14f6d634ed7891fd5d938988b0009a2bc"},
    {1, 0x42, "4552411b08b33667a7989cd9bb4631af4f8b5383f7d81c400a8b9d1f530157eb",
              "ab0c00fb3eff4c4a5793a94903fa8e2560b13c621b372eccc96e6fc82c230bf0"},
    {1, 0xc1, "0100000000000000000000000000000000000000000000000000000000000000",
              "adc201649816aba7b60a040eb6c53a10a5374aa86d70f81336e64e007fbbe8df"},
    {1, 0xc2, "0100000000000000000000000000000000000000000000000000000000000000",
              "e2db30fb67275a2d0806a017037acca2d55174339d90264859a08cdc96435ebd"},
};
const char* const UINT256_ONE_RAW = "0100000000000000000000000000000000000000000000000000000000000000";

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

// The owner's spend: the key item and a signature over the message of witness
// version 11. It is accepted in a block and under relay's flag in every
// combination in which the version runs, and counts one for each check.
BOOST_AUTO_TEST_CASE(a_conforming_v11_spend_is_accepted)
{
    const CTransaction tx(SpendingTx());
    CKey alice, bob;
    alice.MakeNewKey(true);
    bob.MakeNewKey(true);
    const valtype aliceItem = KeyItem(alice), bobItem = KeyItem(bob);

    const CScript one = SingleKeyScript(aliceItem);
    const Spend single = SpendOf(one, {SignV11(alice, one, tx), aliceItem});

    // <hash of B's item> CHECK <hash of A's item> CHECK OP_1: B's pair is on
    // top of A's.
    const CScript two = CScript() << Sha256(bobItem) << OP_CHECKDILITHIUMKEYHASH
                                  << Sha256(aliceItem) << OP_CHECKDILITHIUMKEYHASH << OP_1;
    const Spend twoOfTwo = SpendOf(two, {SignV11(alice, two, tx), aliceItem, SignV11(bob, two, tx), bobItem});

    for (int mask = 1; mask < 8; ++mask) {
        const unsigned int flags = BLOCK | Deployments(mask);
        BOOST_CHECK_MESSAGE(Verdict(single, flags, tx) == SCRIPT_ERR_OK,
            "combination " << mask << ": got " << Name(Verdict(single, flags, tx)));
        BOOST_CHECK_MESSAGE(Verdict(single, flags | RELAY, tx) == SCRIPT_ERR_OK,
            "combination " << mask << " at relay: got " << Name(Verdict(single, flags | RELAY, tx)));
        BOOST_CHECK_MESSAGE(Verdict(twoOfTwo, flags, tx) == SCRIPT_ERR_OK,
            "combination " << mask << ", two keys: got " << Name(Verdict(twoOfTwo, flags, tx)));
        BOOST_CHECK_EQUAL(SigOps(single, flags), 1u);
        BOOST_CHECK_EQUAL(SigOps(twoOfTwo, flags), 2u);
    }
    BOOST_CHECK_EQUAL(SigOps(single, BLOCK), 0u);
    BOOST_CHECK_EQUAL(SigOps(twoOfTwo, BLOCK), 0u);

    // One signature of the two missing, or the two pairs in the other order.
    const Spend oneMissing = SpendOf(two, {SignV11(alice, two, tx), aliceItem, valtype(), bobItem});
    BOOST_CHECK_EQUAL(Verdict(oneMissing, ACTIVE, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
    const Spend swapped = SpendOf(two, {SignV11(bob, two, tx), bobItem, SignV11(alice, two, tx), aliceItem});
    BOOST_CHECK_EQUAL(Verdict(swapped, ACTIVE, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
}

// No hook passes a byte the output did not commit. The key type is inside the
// key hash and the sub-version byte is inside the program, so neither is the
// spender's to choose.
BOOST_AUTO_TEST_CASE(no_hook_passes_before_its_commitment)
{
    const CTransaction tx(SpendingTx());
    CKey owner;
    owner.MakeNewKey(true);
    const valtype ownerItem = KeyItem(owner);
    const CScript script = SingleKeyScript(ownerItem);

    // The committed key under a type byte this release does not define, with
    // an empty signature item and with a signature.
    for (int type : {0x01, 0x02, 0x7f, 0x80, 0xff}) {
        const valtype retyped = KeyItem(owner, static_cast<unsigned char>(type));
        const ScriptError empty = Verdict(SpendOf(script, {valtype(), retyped}), ACTIVE, tx);
        const ScriptError sigV6 = Verdict(SpendOf(script, {SignV6Message(owner, script, tx, SIGHASH_ANYPREVOUTANYSCRIPT), retyped}), ACTIVE, tx);
        BOOST_CHECK_MESSAGE(empty == SCRIPT_ERR_CHECKDILITHIUMKEYHASH,
            "type " << type << ": the key under another type byte must fail at the hash comparison; got " << Name(empty));
        BOOST_CHECK_MESSAGE(sigV6 == SCRIPT_ERR_CHECKDILITHIUMKEYHASH,
            "type " << type << ": the same with a signature must fail at the hash comparison; got " << Name(sigV6));
    }

    // The key without its type byte, and the key item cut or extended.
    const valtype bare(ownerItem.begin() + 1, ownerItem.end());
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {valtype(), bare}), ACTIVE, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {valtype(), valtype(1, 0x05)}), ACTIVE, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {valtype(), valtype()}), ACTIVE, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);

    // The committed item presented under another sub-version byte, against
    // the output that committed 0xc0.
    const valtype sig = SignV11(owner, script, tx);
    const CScript output = OutputFor(CommittedItem(script));
    for (int sub : {0x00, 0xc1, 0xff}) {
        const std::vector<valtype> witness = {sig, ownerItem, CommittedItem(script, static_cast<unsigned char>(sub)), TRAILER};
        BOOST_CHECK_MESSAGE(Verdict(output, witness, ACTIVE, tx) == SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH,
            "sub-version " << sub << ": a changed first byte must be a program mismatch");
    }
    // The script without its sub-version byte, the form witness version 6 commits.
    const std::vector<valtype> noSubversion = {sig, ownerItem, valtype(script.begin(), script.end()), TRAILER};
    BOOST_CHECK_EQUAL(Verdict(output, noSubversion, ACTIVE, tx), SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    // An output that commits the empty item cannot be spent.
    const std::vector<valtype> emptyCommitted = {valtype(), TRAILER};
    BOOST_CHECK_EQUAL(Verdict(OutputFor(valtype()), emptyCommitted, ACTIVE, tx), SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
}

// Each hook succeeds with a block's flags and is refused, with an error of its
// own, under relay's flag. An input that leaves through a sub-version or a
// reserved byte counts nothing; a check on a key of an undefined type counts
// as any other check.
BOOST_AUTO_TEST_CASE(each_hook_succeeds_in_a_block_and_is_refused_under_the_relay_flag)
{
    const CTransaction tx(SpendingTx());

    // A sub-version this release does not define. The bytes after it are not
    // parsed and no other witness item is read.
    for (int sub : {0x00, 0x01, 0xbf, 0xc1, 0xff}) {
        valtype rest = {0x4c};  // a push that runs past the end
        const Spend s = SpendOf(Raw(rest), {valtype(3000, 0x07)}, static_cast<unsigned char>(sub), valtype(1313, 0x00));
        BOOST_CHECK_MESSAGE(Verdict(s, ACTIVE, tx) == SCRIPT_ERR_OK,
            "sub-version " << sub << " in a block: got " << Name(Verdict(s, ACTIVE, tx)));
        BOOST_CHECK_MESSAGE(Verdict(s, ACTIVE | RELAY, tx) == SCRIPT_ERR_DISCOURAGE_UNKNOWN_SUBVERSION,
            "sub-version " << sub << " at relay: got " << Name(Verdict(s, ACTIVE | RELAY, tx)));
        BOOST_CHECK_EQUAL(SigOps(s, ACTIVE), 0u);
    }
    // The count does not read the bytes after such a sub-version byte as a
    // script either.
    const Spend otherLanguage = SpendOf(CScript() << valtype(32, 0x11) << OP_CHECKDILITHIUMKEYHASH << OP_1, {}, 0xc1);
    BOOST_CHECK_EQUAL(Verdict(otherLanguage, ACTIVE, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(SigOps(otherLanguage, ACTIVE), 0u);
    // A committed item that is the sub-version byte alone has an empty script.
    BOOST_CHECK_EQUAL(Verdict(SpendOf(CScript()), ACTIVE, tx), SCRIPT_ERR_EVAL_FALSE);

    // A reserved byte, in the script's own flow, in a branch not taken and
    // behind key-hash checks that would otherwise be counted.
    const valtype h(32, 0x11);
    const CScript reservedScripts[] = {
        CScript() << static_cast<opcodetype>(0xbb),
        CScript() << static_cast<opcodetype>(0xef) << OP_1,
        CScript() << OP_0 << OP_IF << static_cast<opcodetype>(0xd0) << OP_ENDIF << OP_1,
        CScript() << h << OP_CHECKDILITHIUMKEYHASH << h << OP_CHECKDILITHIUMKEYHASH << static_cast<opcodetype>(0xbb),
    };
    for (const CScript& script : reservedScripts) {
        const Spend s = SpendOf(script, {valtype(3000, 0x07)}, 0xc0, valtype(1313, 0x00));
        BOOST_CHECK_MESSAGE(Verdict(s, ACTIVE, tx) == SCRIPT_ERR_OK,
            "a reserved byte in a block: got " << Name(Verdict(s, ACTIVE, tx)));
        BOOST_CHECK_MESSAGE(Verdict(s, ACTIVE | RELAY, tx) == SCRIPT_ERR_DISCOURAGE_RESERVED_OPCODE,
            "a reserved byte at relay: got " << Name(Verdict(s, ACTIVE | RELAY, tx)));
        BOOST_CHECK_EQUAL(SigOps(s, ACTIVE), 0u);
    }

    // A key of a type this release does not define, committed by the script:
    // the check passes whatever the length of the key item and the content of
    // the signature item, and the script goes on.
    const valtype unknownKeys[] = {valtype(1, 0x01), valtype(1313, 0x01), valtype(40, 0xff), valtype(2421, 0x02)};
    const valtype signatureItems[] = {valtype(), valtype(1, 0x42), valtype(2421, 0x00)};
    for (const valtype& keyItem : unknownKeys) {
        for (const valtype& sigItem : signatureItems) {
            const Spend s = SpendOf(SingleKeyScript(keyItem), {sigItem, keyItem});
            BOOST_CHECK_MESSAGE(Verdict(s, ACTIVE, tx) == SCRIPT_ERR_OK,
                "a key of type " << int(keyItem[0]) << " in a block: got " << Name(Verdict(s, ACTIVE, tx)));
            BOOST_CHECK_MESSAGE(Verdict(s, ACTIVE | RELAY, tx) == SCRIPT_ERR_DISCOURAGE_UNKNOWN_KEYTYPE,
                "a key of type " << int(keyItem[0]) << " at relay: got " << Name(Verdict(s, ACTIVE | RELAY, tx)));
            BOOST_CHECK_EQUAL(SigOps(s, ACTIVE), 1u);
        }
    }

    // The stack after a check on such a key is the stack after a verified
    // check: a script of one key of each kind needs the one signature.
    CKey alice;
    alice.MakeNewKey(true);
    const valtype aliceItem = KeyItem(alice);
    const valtype later(33, 0x09);
    const CScript mixed = CScript() << Sha256(later) << OP_CHECKDILITHIUMKEYHASH
                                    << Sha256(aliceItem) << OP_CHECKDILITHIUMKEYHASH << OP_1;
    BOOST_CHECK_EQUAL(Verdict(SpendOf(mixed, {SignV11(alice, mixed, tx), aliceItem, valtype(), later}), ACTIVE, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(mixed, {valtype(), aliceItem, valtype(), later}), ACTIVE, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
}

// A script that commits the hash of the key without its type byte, the hash a
// witness version 6 script carries, is spent with no signature by anyone who
// has seen the key: the bare key matches the hash and its first byte reads as
// a key type. Pinned so that no builder assumes otherwise; relay refuses the
// spend.
BOOST_AUTO_TEST_CASE(a_script_that_commits_the_bare_key_is_spent_without_a_signature)
{
    const CTransaction tx(SpendingTx());
    valtype bare;
    do {
        CKey key;
        key.MakeNewKey(true);
        const CPubKey pub = key.GetPubKey();
        bare.assign(pub.begin(), pub.end());
    } while (bare[0] == 0x00);
    BOOST_REQUIRE_EQUAL(bare.size(), 1312u);

    const Spend s = SpendOf(SingleKeyScript(bare), {valtype(), bare});
    BOOST_CHECK_EQUAL(Verdict(s, ACTIVE, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(s, ACTIVE | RELAY, tx), SCRIPT_ERR_DISCOURAGE_UNKNOWN_KEYTYPE);
}

// The walk reads the script in order. A push that fails to decode before any
// reserved byte fails the input; the first reserved byte passes it, whatever
// follows; a refused byte fails it only if no reserved byte follows; a
// reserved value inside push data is data.
BOOST_AUTO_TEST_CASE(the_walk_orders_a_failed_decode_a_reserved_byte_and_a_refused_byte)
{
    const CTransaction tx(SpendingTx());
    const unsigned char R = 0xbb;

    // A failed decode, then a reserved byte it swallowed.
    BOOST_CHECK_EQUAL(Verdict(SpendOf(Raw({0x02, R})), ACTIVE, tx), SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(Raw({0x4c, 0x05, R})), ACTIVE, tx), SCRIPT_ERR_BAD_OPCODE);
    // A reserved byte, then a push that runs past the end.
    BOOST_CHECK_EQUAL(Verdict(SpendOf(Raw({R, 0x4c, 0x05})), ACTIVE, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(Raw({R, 0x02})), ACTIVE, tx), SCRIPT_ERR_OK);
    // A refused byte, then a reserved byte.
    BOOST_CHECK_EQUAL(Verdict(SpendOf(Raw({OP_CHECKSIG, R})), ACTIVE, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(Raw({OP_CHECKPATAGG, OP_DUP, R})), ACTIVE, tx), SCRIPT_ERR_OK);
    // A reserved byte, then a refused byte.
    BOOST_CHECK_EQUAL(Verdict(SpendOf(Raw({R, OP_CHECKSIG})), ACTIVE, tx), SCRIPT_ERR_OK);
    // Refused bytes and no reserved byte: the error of the first.
    BOOST_CHECK_EQUAL(Verdict(SpendOf(Raw({OP_1, OP_CHECKSIG, OP_CHECKPATAGG})), ACTIVE, tx), SCRIPT_ERR_DISALLOWED_OPCODE);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(Raw({OP_1, OP_CHECKPATAGG, OP_CHECKSIG})), ACTIVE, tx), SCRIPT_ERR_BAD_OPCODE);
    // A refused byte, then a push that runs past the end.
    BOOST_CHECK_EQUAL(Verdict(SpendOf(Raw({OP_CHECKSIG, 0x02})), ACTIVE, tx), SCRIPT_ERR_BAD_OPCODE);
    // Reserved and refused values inside push data.
    BOOST_CHECK_EQUAL(Verdict(SpendOf(Raw({0x03, R, OP_CHECKSIG, 0xef})), ACTIVE | RELAY, tx), SCRIPT_ERR_OK);
}

// All 256 bytes in each of the seven combinations in which the version runs.
// A defined opcode reaches its handler, a reserved byte passes the script
// unevaluated in a block and is refused at relay, a refused byte fails the
// script before evaluation; the last two in a branch that is not taken as
// well. No byte is skipped in any state.
BOOST_AUTO_TEST_CASE(every_byte_has_one_class_in_every_flag_state)
{
    const CTransaction tx(SpendingTx());
    for (int mask = 1; mask < 8; ++mask) {
        const unsigned int flags = BLOCK | Deployments(mask);
        int defined = 0, reserved = 0, refused = 0, refusedBadOpcode = 0;
        for (int b = 0; b <= 0xff; ++b) {
            const opcodetype op = static_cast<opcodetype>(b);
            const ScriptError alone = Verdict(SpendOf(CScript() << op), flags, tx);
            const ScriptError notTaken = Verdict(SpendOf(CScript() << OP_0 << OP_IF << op << OP_ENDIF << OP_1), flags, tx);
            const std::string where = "byte " + std::to_string(b) + ", combination " + std::to_string(mask) + ": ";
            switch (ExpectedClass(b, flags)) {
            case CLASS_PUSH: {
                ++defined;
                valtype raw = PushBytes(b);
                raw.push_back(OP_DROP);
                raw.push_back(OP_1);
                const ScriptError pushed = Verdict(SpendOf(Raw(raw)), flags | RELAY, tx);
                BOOST_CHECK_MESSAGE(pushed == SCRIPT_ERR_OK, where << "a push must run; got " << Name(pushed));
                break;
            }
            case CLASS_DEFINED:
                ++defined;
                BOOST_CHECK_MESSAGE(alone == SCRIPT_ERR_INVALID_STACK_OPERATION || alone == SCRIPT_ERR_UNBALANCED_CONDITIONAL,
                    where << "a defined opcode must reach its handler, which objects to the empty stack; got " << Name(alone));
                break;
            case CLASS_RESERVED: {
                ++reserved;
                BOOST_CHECK_MESSAGE(alone == SCRIPT_ERR_OK, where << "a reserved byte must pass the script; got " << Name(alone));
                BOOST_CHECK_MESSAGE(notTaken == SCRIPT_ERR_OK, where << "and in a branch not taken; got " << Name(notTaken));
                const ScriptError atRelay = Verdict(SpendOf(CScript() << op), flags | RELAY, tx);
                BOOST_CHECK_MESSAGE(atRelay == SCRIPT_ERR_DISCOURAGE_RESERVED_OPCODE, where << "and be refused at relay; got " << Name(atRelay));
                break;
            }
            case CLASS_REFUSED_BAD_OPCODE:
            case CLASS_REFUSED_DISALLOWED: {
                ++refused;
                const bool badOpcode = ExpectedClass(b, flags) == CLASS_REFUSED_BAD_OPCODE;
                if (badOpcode)
                    ++refusedBadOpcode;
                const ScriptError expected = badOpcode ? SCRIPT_ERR_BAD_OPCODE : SCRIPT_ERR_DISALLOWED_OPCODE;
                BOOST_CHECK_MESSAGE(alone == expected, where << "a refused byte must fail before evaluation; got " << Name(alone));
                BOOST_CHECK_MESSAGE(notTaken == expected, where << "and in a branch not taken; got " << Name(notTaken));
                break;
            }
            }
        }
        const int ctv = (flags & SCRIPT_VERIFY_CTV) ? 1 : 0;
        const int csfs = (flags & SCRIPT_VERIFY_CSFS) ? 1 : 0;
        // 95 pushes (79 from 0x00 to 0x4e, 16 from 0x51 to 0x60) and 22 opcodes
        // are defined in every state; 0xbb to 0xef is 53 bytes.
        BOOST_CHECK_EQUAL(defined, 95 + 22 + ctv + csfs);
        BOOST_CHECK_EQUAL(reserved, 53 + (1 - ctv) + (1 - csfs));
        BOOST_CHECK_EQUAL(refused, 84);
        BOOST_CHECK_EQUAL(refusedBadOpcode, 7);
        BOOST_CHECK_EQUAL(defined + reserved + refused, 256);
    }
}

// The hash types of an ML-DSA-44 key are a closed list of six. Every other
// value of the byte fails before a message is computed, whichever message the
// signature was made over and whether or not the anyprevout deployment is
// active.
BOOST_AUTO_TEST_CASE(the_hash_type_list_of_an_ml_dsa_44_key_is_closed)
{
    const CTransaction tx(SpendingTx());
    CKey owner;
    owner.MakeNewKey(true);
    const valtype ownerItem = KeyItem(owner);
    const CScript script = SingleKeyScript(ownerItem);
    const unsigned int withApo = ACTIVE;
    const unsigned int withoutApo = BLOCK | SCRIPT_VERIFY_CTV | SCRIPT_VERIFY_CSFS;

    int admitted = 0;
    for (int b = 0; b <= 0xff; ++b) {
        // The strongest attempt: a signature by the owner over what
        // SignatureHash returns for this byte under the new signature version.
        valtype sig = SignHash(owner, SignatureHash(script, tx, 0, b, AMOUNT, SIGVERSION_WITNESS_V11, nullptr, 0x00));
        sig.push_back(static_cast<unsigned char>(b));
        const Spend s = SpendOf(script, {sig, ownerItem});
        const bool listed = (b == 0x01 || b == 0x02 || b == 0x03 || b == 0x81 || b == 0x82 || b == 0x83);
        const ScriptError expected = listed ? SCRIPT_ERR_OK : SCRIPT_ERR_SIG_HASHTYPE;
        if (listed)
            ++admitted;
        for (unsigned int flags : {withApo, withoutApo, withApo | RELAY}) {
            const ScriptError got = Verdict(s, flags, tx);
            BOOST_CHECK_MESSAGE(got == expected, "hash type " << b << ": expected " << Name(expected) << ", got " << Name(got));
        }
    }
    BOOST_CHECK_EQUAL(admitted, 6);

    // The anyprevout types over the message witness version 6 computes for
    // them, and the two values for which that function returns a constant,
    // signed over the constant.
    for (int b : {0x41, 0x42}) {
        const Spend s = SpendOf(script, {SignV6Message(owner, script, tx, b), ownerItem});
        BOOST_CHECK_EQUAL(Verdict(s, withApo, tx), SCRIPT_ERR_SIG_HASHTYPE);
    }
    for (int b : {0xc1, 0xc2}) {
        valtype sig = SignHash(owner, uint256S("0x0000000000000000000000000000000000000000000000000000000000000001"));
        sig.push_back(static_cast<unsigned char>(b));
        BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {sig, ownerItem}), withApo, tx), SCRIPT_ERR_SIG_HASHTYPE);
    }
}

// SIGHASH_SINGLE signs the output at the input's index. Where the transaction
// has no output there, the check fails; the signature is not checked against
// a message over no output.
BOOST_AUTO_TEST_CASE(a_single_hash_type_with_no_output_at_the_inputs_index_fails)
{
    CMutableTransaction mtx = SpendingTx();
    CTxIn second;
    second.prevout = COutPoint(uint256S("0x3333333333333333333333333333333333333333333333333333333333333333"), 1);
    second.nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vin.push_back(second);
    const CTransaction tx(mtx);  // two inputs, one output
    CKey owner;
    owner.MakeNewKey(true);
    const valtype ownerItem = KeyItem(owner);
    const CScript script = SingleKeyScript(ownerItem);

    for (int b : {0x03, 0x83}) {
        // Input 1, no output 1: signed over what SignatureHash returns.
        valtype sig = SignHash(owner, SignatureHash(script, tx, 1, b, AMOUNT, SIGVERSION_WITNESS_V11, nullptr, 0x00));
        sig.push_back(static_cast<unsigned char>(b));
        const Spend noOutput = SpendOf(script, {sig, ownerItem});
        BOOST_CHECK_MESSAGE(Verdict(noOutput.output, noOutput.witness, ACTIVE, tx, 1) == SCRIPT_ERR_CHECKDILITHIUMKEYHASH,
            "hash type " << b << " at an input with no output at its index must fail");
        // Input 0 has output 0.
        const Spend withOutput = SpendOf(script, {SignV11(owner, script, tx, b, 0), ownerItem});
        BOOST_CHECK_EQUAL(Verdict(withOutput.output, withOutput.witness, ACTIVE, tx, 0), SCRIPT_ERR_OK);
    }
    // The other four at input 1.
    for (int b : {0x01, 0x02, 0x81, 0x82}) {
        const Spend s = SpendOf(script, {SignV11(owner, script, tx, b, 1), ownerItem});
        BOOST_CHECK_MESSAGE(Verdict(s.output, s.witness, ACTIVE, tx, 1) == SCRIPT_ERR_OK, "hash type " << b << " at input 1");
    }

    // An input index outside the transaction has no message either: a
    // signature over the constant SignatureHash returns for it does not verify.
    valtype overOne = SignHash(owner, uint256S("0x0000000000000000000000000000000000000000000000000000000000000001"));
    overOne.push_back(SIGHASH_ALL);
    BOOST_CHECK(SignatureHash(script, tx, 5, SIGHASH_ALL, AMOUNT, SIGVERSION_WITNESS_V11, nullptr, 0x00) ==
                uint256S("0x0000000000000000000000000000000000000000000000000000000000000001"));
    const TransactionSignatureChecker outside(&tx, 5, AMOUNT);
    BOOST_CHECK(!outside.CheckSig(overOne, ownerItem, script, SIGVERSION_WITNESS_V11));
}

// A key item of the ML-DSA-44 type is 1,313 bytes and nothing else, and its
// signature item is a signature and a hash type byte.
BOOST_AUTO_TEST_CASE(a_key_item_of_type_0x00_is_1313_bytes_and_its_signature_verifies)
{
    const CTransaction tx(SpendingTx());
    CKey owner, other;
    owner.MakeNewKey(true);
    other.MakeNewKey(true);
    const valtype ownerItem = KeyItem(owner);
    const CScript script = SingleKeyScript(ownerItem);
    const valtype sig = SignV11(owner, script, tx);

    // Items of type 0x00 with another length, each committed by its own script.
    valtype shorter(ownerItem.begin(), ownerItem.end() - 1);
    valtype longer = ownerItem;
    longer.push_back(0x00);
    for (const valtype& item : {valtype(1, 0x00), shorter, longer, valtype(2421, 0x00)}) {
        const CScript s = SingleKeyScript(item);
        const ScriptError got = Verdict(SpendOf(s, {SignV11(owner, s, tx), item}), ACTIVE, tx);
        BOOST_CHECK_MESSAGE(got == SCRIPT_ERR_CHECKDILITHIUMKEYHASH,
            "a key item of type 0x00 and " << item.size() << " bytes must fail; got " << Name(got));
        BOOST_CHECK_EQUAL(Verdict(SpendOf(s, {valtype(), item}), ACTIVE | RELAY, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
    }

    // The signature item: empty, the signature without its hash type byte, a
    // signature by another key, and the signature with one bit changed.
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {valtype(), ownerItem}), ACTIVE, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
    const valtype noHashType(sig.begin(), sig.end() - 1);
    BOOST_CHECK(Verdict(SpendOf(script, {noHashType, ownerItem}), ACTIVE, tx) != SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {SignV11(other, script, tx), ownerItem}), ACTIVE, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
    valtype flipped = sig;
    flipped[100] ^= 0x01;
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {flipped, ownerItem}), ACTIVE, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);

    // A signature made for another transaction, and one made for the same key
    // committed under another type byte.
    CMutableTransaction otherTx = SpendingTx();
    otherTx.vout[0].nValue -= 1;
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {SignV11(owner, script, CTransaction(otherTx)), ownerItem}), ACTIVE, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {SignV11(owner, script, tx, SIGHASH_ALL, 0, 0x01), ownerItem}), ACTIVE, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {sig, ownerItem}), ACTIVE, tx), SCRIPT_ERR_OK);

    // CheckSig under the new signature version verifies an ML-DSA-44 key item
    // and no other: the same key under another type byte, with a signature
    // over the message that names that type, is not verified, and neither is
    // the key without a type byte.
    const TransactionSignatureChecker checker(&tx, 0, AMOUNT);
    BOOST_CHECK(checker.CheckSig(sig, ownerItem, script, SIGVERSION_WITNESS_V11));
    BOOST_CHECK(!checker.CheckSig(SignV11(owner, script, tx, SIGHASH_ALL, 0, 0x01), KeyItem(owner, 0x01), script, SIGVERSION_WITNESS_V11));
    BOOST_CHECK(!checker.CheckSig(sig, valtype(ownerItem.begin() + 1, ownerItem.end()), script, SIGVERSION_WITNESS_V11));
}

// OP_CHECKSIGFROMSTACK takes its key from the witness with no hash to bind it,
// so it takes the ML-DSA-44 key item and fails on every other key: no key
// type passes it unverified.
BOOST_AUTO_TEST_CASE(checksigfromstack_takes_the_ml_dsa_44_key_item_and_nothing_else)
{
    const CTransaction tx(SpendingTx());
    CKey oracle;
    oracle.MakeNewKey(true);
    const valtype oracleItem = KeyItem(oracle);
    const valtype message = {'p', 'r', 'i', 'c', 'e'};
    const valtype sig = SignHash(oracle, Hash(message.begin(), message.end()));
    const CScript script = CScript() << OP_CHECKSIGFROMSTACK << OP_1;

    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {sig, message, oracleItem}), ACTIVE, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {sig, message, oracleItem}), ACTIVE | RELAY, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(SigOps(SpendOf(script, {sig, message, oracleItem}), ACTIVE), 1u);

    // The key without its type byte, which witness version 6 accepts.
    const valtype bare(oracleItem.begin() + 1, oracleItem.end());
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {sig, message, bare}), ACTIVE, tx), SCRIPT_ERR_CHECKSIGFROMSTACK);
    // The key under other type bytes, and items of other lengths.
    for (int type : {0x01, 0x02, 0xff}) {
        const valtype retyped = KeyItem(oracle, static_cast<unsigned char>(type));
        BOOST_CHECK_MESSAGE(Verdict(SpendOf(script, {sig, message, retyped}), ACTIVE, tx) == SCRIPT_ERR_CHECKSIGFROMSTACK,
            "a key item of type " << type << " must fail in a block");
        BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {valtype(), message, retyped}), ACTIVE, tx), SCRIPT_ERR_CHECKSIGFROMSTACK);
    }
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {sig, message, valtype(1, 0x05)}), ACTIVE, tx), SCRIPT_ERR_CHECKSIGFROMSTACK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {sig, message, valtype()}), ACTIVE, tx), SCRIPT_ERR_CHECKSIGFROMSTACK);
    // Another message, and another signer.
    const valtype otherMessage = {'p', 'r', 'i', 'c', 'f'};
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {sig, otherMessage, oracleItem}), ACTIVE, tx), SCRIPT_ERR_CHECKSIGFROMSTACK);
    CKey mallory;
    mallory.MakeNewKey(true);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {SignHash(mallory, Hash(message.begin(), message.end())), message, oracleItem}), ACTIVE, tx), SCRIPT_ERR_CHECKSIGFROMSTACK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {message, oracleItem}), ACTIVE, tx), SCRIPT_ERR_INVALID_STACK_OPERATION);

    // With the opcode's deployment inactive the byte is reserved: the script
    // passes unevaluated in a block, is refused at relay, and counts nothing.
    const unsigned int noCsfs = BLOCK | SCRIPT_VERIFY_CTV | SCRIPT_VERIFY_APO;
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {sig, otherMessage, bare}), noCsfs, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {sig, message, oracleItem}), noCsfs | RELAY, tx), SCRIPT_ERR_DISCOURAGE_RESERVED_OPCODE);
    BOOST_CHECK_EQUAL(SigOps(SpendOf(script, {sig, message, oracleItem}), noCsfs), 0u);
}

// The rules of the script language bind a script this release evaluates: the
// script at most 10,000 bytes, at most 1,000 satisfaction items of at most
// 2,421 bytes, an empty scriptSig, and a trailer of the one byte 0x00. None
// of them binds an input that leaves through a sub-version or a reserved byte.
BOOST_AUTO_TEST_CASE(the_rules_of_the_script_language_bind_an_evaluated_script_only)
{
    const CTransaction tx(SpendingTx());

    // The size of the script, which is the committed item less its first byte.
    BOOST_CHECK_EQUAL(Verdict(SpendOf(ScriptOfSize(10000)), ACTIVE, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(ScriptOfSize(10001)), ACTIVE, tx), SCRIPT_ERR_SCRIPT_SIZE);

    // The number of satisfaction items.
    CScript dropAll;
    for (int i = 0; i < 1000; ++i)
        dropAll << OP_DROP;
    dropAll << OP_1;
    BOOST_CHECK_EQUAL(Verdict(SpendOf(dropAll, std::vector<valtype>(1000, valtype(1, 0x01))), ACTIVE, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(dropAll, std::vector<valtype>(1001, valtype(1, 0x01))), ACTIVE, tx), SCRIPT_ERR_STACK_SIZE);

    // The size of a satisfaction item.
    const CScript dropOne = CScript() << OP_DROP << OP_1;
    BOOST_CHECK_EQUAL(Verdict(SpendOf(dropOne, {valtype(2421, 0x01)}), ACTIVE, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(dropOne, {valtype(2422, 0x01)}), ACTIVE, tx), SCRIPT_ERR_PUSH_SIZE);
    // The figure binds the items of a key of an undefined type, whose check
    // runs inside an evaluated script.
    const valtype bigKey(2422, 0x07);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(SingleKeyScript(bigKey), {valtype(), bigKey}), ACTIVE, tx), SCRIPT_ERR_PUSH_SIZE);

    // The trailer.
    const CScript trueScript = CScript() << OP_1;
    const valtype trailers[] = {valtype(), valtype(1, 0x01), valtype(2, 0x00), valtype(1313, 0x00)};
    for (const valtype& trailer : trailers) {
        const ScriptError got = Verdict(SpendOf(trueScript, {}, 0xc0, trailer), ACTIVE, tx);
        BOOST_CHECK_MESSAGE(got == SCRIPT_ERR_WITNESS_V11_TRAILER,
            "a trailer of " << trailer.size() << " bytes must be refused; got " << Name(got));
    }
    BOOST_CHECK_EQUAL(Verdict(SpendOf(trueScript), ACTIVE, tx), SCRIPT_ERR_OK);

    // The end rule: exactly one item is left, and it is true.
    BOOST_CHECK_EQUAL(Verdict(SpendOf(CScript() << OP_1 << OP_1), ACTIVE, tx), SCRIPT_ERR_EVAL_FALSE);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(trueScript, {valtype(1, 0x01)}), ACTIVE, tx), SCRIPT_ERR_EVAL_FALSE);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(CScript() << OP_0), ACTIVE, tx), SCRIPT_ERR_EVAL_FALSE);

    // The scriptSig.
    const Spend plain = SpendOf(trueScript);
    BOOST_CHECK_EQUAL(Verdict(plain.output, plain.witness, ACTIVE, tx, 0, CScript() << OP_0), SCRIPT_ERR_WITNESS_MALLEATED);
    BOOST_CHECK_EQUAL(Verdict(plain.output, plain.witness, ACTIVE, tx, 0, CScript() << valtype(4, 0x01)), SCRIPT_ERR_WITNESS_MALLEATED);

    // An input that leaves through a hook is outside every one of them.
    CScript bigReserved = ScriptOfSize(10001);
    bigReserved << static_cast<opcodetype>(0xbb);
    const Spend hooks[] = {
        SpendOf(bigReserved, std::vector<valtype>(1001, valtype(2422, 0x01)), 0xc0, valtype(1313, 0x00)),
        SpendOf(ScriptOfSize(10001), std::vector<valtype>(1001, valtype(2422, 0x01)), 0xc1, valtype(1313, 0x00)),
    };
    for (const Spend& s : hooks) {
        BOOST_CHECK_EQUAL(Verdict(s.output, s.witness, ACTIVE, tx, 0, CScript() << OP_0), SCRIPT_ERR_OK);
        BOOST_CHECK(Verdict(s.output, s.witness, ACTIVE | RELAY, tx, 0, CScript() << OP_0) != SCRIPT_ERR_OK);
    }
}

// OP_MUL takes operands of up to eight bytes and fails when the product is
// outside the range a script number of eight bytes holds. That range has no
// INT64_MIN: the version refuses every pair of operands that multiplies to it,
// as it refuses an overflow, and accepts the products beside it. The case
// takes one such pair of magnitudes in its four arrangements.
BOOST_AUTO_TEST_CASE(op_mul_refuses_a_product_outside_the_eight_byte_range)
{
    const CTransaction tx(SpendingTx());
    const int64_t two32 = 4294967296LL;
    const int64_t two31 = 2147483648LL;
    auto product = [&](int64_t a, int64_t b) {
        return Verdict(SpendOf(CScript() << CScriptNum(a) << CScriptNum(b) << OP_MUL << OP_DROP << OP_1), ACTIVE, tx);
    };

    // -2^32 * 2^31 = -2^63, in either order and with either sign negative.
    BOOST_CHECK_EQUAL(product(-two32, two31), SCRIPT_ERR_PUSH_SIZE);
    BOOST_CHECK_EQUAL(product(two31, -two32), SCRIPT_ERR_PUSH_SIZE);
    BOOST_CHECK_EQUAL(product(two32, -two31), SCRIPT_ERR_PUSH_SIZE);
    BOOST_CHECK_EQUAL(product(-two31, two32), SCRIPT_ERR_PUSH_SIZE);
    // 2^63 and above overflow, as before.
    BOOST_CHECK_EQUAL(product(two32, two31), SCRIPT_ERR_PUSH_SIZE);
    BOOST_CHECK_EQUAL(product(-two32, -two31), SCRIPT_ERR_PUSH_SIZE);
    // The products beside the refused one are accepted: -(2^63 - 2^32) and
    // its mirror, and the largest and smallest values an operand can hold
    // multiplied by one.
    BOOST_CHECK_EQUAL(product(-two32, two31 - 1), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(product(two32, two31 - 1), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(product(INT64_MAX, 1), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(product(INT64_MAX, -1), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(product(-INT64_MAX, -1), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(product(0, -two32), SCRIPT_ERR_OK);

    // The accepted product is the number it should be: -(2^63 - 2^32)
    // divided by -2^32 is 2^31 - 1.
    const CScript check = CScript() << CScriptNum(-two32) << CScriptNum(two31 - 1) << OP_MUL
                                    << CScriptNum(-two32) << OP_DIV << CScriptNum(two31 - 1) << OP_EQUAL;
    BOOST_CHECK_EQUAL(Verdict(SpendOf(check), ACTIVE, tx), SCRIPT_ERR_OK);
}

// The hash operand of the key-hash check is exactly 32 bytes, an empty key
// item fails, and the count reads an empty committed item as no script.
// OP_CHECKSEQUENCEVERIFY compares its operand with the input's sequence.
BOOST_AUTO_TEST_CASE(the_key_hash_operand_is_32_bytes_and_an_empty_key_item_fails)
{
    const CTransaction tx(SpendingTx());
    CKey owner;
    owner.MakeNewKey(true);
    const valtype ownerItem = KeyItem(owner);

    // The hash of the key item with one byte after it, and without its last
    // byte. The signature is valid for the script that holds the operand.
    valtype longer = Sha256(ownerItem);
    longer.push_back(0x00);
    valtype shorter = Sha256(ownerItem);
    shorter.pop_back();
    for (const valtype& operand : {longer, shorter}) {
        const CScript script = CScript() << operand << OP_CHECKDILITHIUMKEYHASH << OP_1;
        const ScriptError got = Verdict(SpendOf(script, {SignV11(owner, script, tx), ownerItem}), ACTIVE, tx);
        BOOST_CHECK_MESSAGE(got == SCRIPT_ERR_CHECKDILITHIUMKEYHASH,
            "a hash operand of " << operand.size() << " bytes must fail; got " << Name(got));
    }

    // An empty key item has no type byte. It fails under a script that
    // commits the hash of the empty item, with a block's flags and at relay,
    // whatever the signature item holds.
    const CScript emptyKeyScript = SingleKeyScript(valtype());
    BOOST_CHECK_EQUAL(Verdict(SpendOf(emptyKeyScript, {valtype(), valtype()}), ACTIVE, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(emptyKeyScript, {valtype(1, 0x01), valtype()}), ACTIVE | RELAY, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);

    // A committed item that is empty: the program can commit it, the input
    // fails, and the count is zero.
    Spend emptyCommitted;
    emptyCommitted.output = OutputFor(valtype());
    emptyCommitted.witness = {valtype(), TRAILER};
    BOOST_CHECK_EQUAL(Verdict(emptyCommitted, ACTIVE, tx), SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
    BOOST_CHECK_EQUAL(SigOps(emptyCommitted, ACTIVE), 0u);

    // The relative lock: an input whose sequence is 5 satisfies an operand of
    // 5 and not one of 6.
    CMutableTransaction mtx = SpendingTx();
    mtx.vin[0].nSequence = 5;
    const CTransaction relative(mtx);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(CScript() << CScriptNum(5) << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_1), ACTIVE, relative), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(CScript() << CScriptNum(6) << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_1), ACTIVE, relative), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

// The argument of OP_IF and OP_NOTIF is the empty item or the one byte 0x01,
// as a rule of the version, with a block's flags.
BOOST_AUTO_TEST_CASE(the_argument_of_a_branch_is_the_empty_item_or_the_byte_one)
{
    const CTransaction tx(SpendingTx());
    const CScript script = CScript() << OP_IF << OP_1 << OP_ELSE << OP_1 << OP_ENDIF;
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {valtype(1, 0x01)}), ACTIVE, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(script, {valtype()}), ACTIVE, tx), SCRIPT_ERR_OK);
    const valtype others[] = {valtype(1, 0x02), valtype(1, 0x00), valtype(1, 0x80), valtype(2, 0x01), valtype(2, 0x00)};
    for (const valtype& arg : others) {
        const ScriptError got = Verdict(SpendOf(script, {arg}), ACTIVE, tx);
        BOOST_CHECK_MESSAGE(got == SCRIPT_ERR_MINIMALIF, "an argument of " << HexStr(arg) << " must be refused; got " << Name(got));
    }
    const CScript notIf = CScript() << OP_NOTIF << OP_1 << OP_ELSE << OP_1 << OP_ENDIF;
    BOOST_CHECK_EQUAL(Verdict(SpendOf(notIf, {valtype(1, 0x02)}), ACTIVE, tx), SCRIPT_ERR_MINIMALIF);
    // An argument the script computes: the results of OP_EQUAL are the two
    // admitted values.
    const CScript computed = CScript() << OP_1 << OP_EQUAL << OP_IF << OP_1 << OP_ELSE << OP_1 << OP_ENDIF;
    BOOST_CHECK_EQUAL(Verdict(SpendOf(computed, {valtype(1, 0x01)}), ACTIVE, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(SpendOf(computed, {valtype(1, 0x02)}), ACTIVE, tx), SCRIPT_ERR_OK);
}

// Each successful check pops its three operands and pushes nothing, so no
// signature item serves two checks. EvalScript, called directly under the new
// signature version, refuses a byte that is not defined.
BOOST_AUTO_TEST_CASE(each_check_leaves_the_stack_three_items_shorter)
{
    const CTransaction tx(SpendingTx());
    const TransactionSignatureChecker checker(&tx, 0, AMOUNT);
    CKey owner;
    owner.MakeNewKey(true);
    const valtype ownerItem = KeyItem(owner);
    const valtype marker(1, 0x77);
    ScriptError serr = SCRIPT_ERR_OK;

    // A verified key-hash check.
    {
        const CScript script = CScript() << Sha256(ownerItem) << OP_CHECKDILITHIUMKEYHASH;
        std::vector<valtype> stack = {marker, SignV11(owner, script, tx), ownerItem};
        BOOST_CHECK(EvalScript(stack, script, ACTIVE, checker, SIGVERSION_WITNESS_V11, &serr));
        BOOST_CHECK(stack == std::vector<valtype>(1, marker));
    }
    // A key-hash check on a key of an undefined type.
    {
        const valtype later(40, 0x05);
        const CScript script = CScript() << Sha256(later) << OP_CHECKDILITHIUMKEYHASH;
        std::vector<valtype> stack = {marker, valtype(9, 0x01), later};
        BOOST_CHECK(EvalScript(stack, script, ACTIVE, checker, SIGVERSION_WITNESS_V11, &serr));
        BOOST_CHECK(stack == std::vector<valtype>(1, marker));
    }
    // OP_CHECKSIGFROMSTACK.
    {
        const valtype message(20, 0x33);
        const CScript script = CScript() << OP_CHECKSIGFROMSTACK;
        std::vector<valtype> stack = {marker, SignHash(owner, Hash(message.begin(), message.end())), message, ownerItem};
        BOOST_CHECK(EvalScript(stack, script, ACTIVE, checker, SIGVERSION_WITNESS_V11, &serr));
        BOOST_CHECK(stack == std::vector<valtype>(1, marker));
    }
    // A second check on the same signature item finds it gone.
    {
        const CScript script = CScript() << Sha256(ownerItem) << OP_CHECKDILITHIUMKEYHASH
                                         << Sha256(ownerItem) << OP_CHECKDILITHIUMKEYHASH;
        std::vector<valtype> stack = {SignV11(owner, script, tx), ownerItem};
        BOOST_CHECK(!EvalScript(stack, script, ACTIVE, checker, SIGVERSION_WITNESS_V11, &serr));
        BOOST_CHECK_EQUAL(serr, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // The guard in EvalScript: every byte that is not defined, executed or in
    // a branch that is not taken.
    for (int b = 0; b <= 0xff; ++b) {
        if (ExpectedClass(b, ACTIVE) == CLASS_PUSH || ExpectedClass(b, ACTIVE) == CLASS_DEFINED)
            continue;
        const opcodetype op = static_cast<opcodetype>(b);
        for (const CScript& script : {CScript() << OP_1 << op, CScript() << OP_0 << OP_IF << op << OP_ENDIF << OP_1}) {
            std::vector<valtype> stack;
            BOOST_CHECK_MESSAGE(!EvalScript(stack, script, ACTIVE, checker, SIGVERSION_WITNESS_V11, &serr) && serr == SCRIPT_ERR_BAD_OPCODE,
                "byte " << b << " must be refused by EvalScript under the new signature version; got " << Name(serr));
        }
    }
    // The same two bytes are reserved to EvalScript while their flag is clear.
    for (opcodetype op : {OP_CHECKTEMPLATEVERIFY, OP_CHECKSIGFROMSTACK}) {
        std::vector<valtype> stack = {valtype(32, 0x01)};
        const CScript script = CScript() << op;
        BOOST_CHECK(!EvalScript(stack, script, BLOCK | SCRIPT_VERIFY_APO, checker, SIGVERSION_WITNESS_V11, &serr));
        BOOST_CHECK_EQUAL(serr, SCRIPT_ERR_BAD_OPCODE);
    }
}

// A checker computes the template hash of its transaction and input once,
// however many times a script executes OP_CHECKTEMPLATEVERIFY, and every
// execution compares the hash it is given with that value.
BOOST_AUTO_TEST_CASE(a_checker_computes_the_template_hash_once)
{
    auto verdict = [](const Spend& s, const CountingChecker& checker) {
        CScriptWitness w;
        w.stack = s.witness;
        ScriptError serr = SCRIPT_ERR_OK;
        VerifyScript(CScript(), s.output, &w, ACTIVE, checker, &serr);
        return serr;
    };

    const CTransaction tx(VectorTx());
    const valtype right0 = TemplateHash(tx, 0);
    const valtype right1 = TemplateHash(tx, 1);
    BOOST_REQUIRE(right0 != right1);
    valtype wrong = right0;
    wrong[31] ^= 0x80;

    // The longest script the version evaluates: one push of the hash and
    // 9,967 executions of the opcode.
    CScript many;
    many << right0;
    for (int i = 0; i < 9967; ++i)
        many << OP_CHECKTEMPLATEVERIFY;
    BOOST_REQUIRE_EQUAL(many.size(), 10000u);
    {
        CountingChecker checker(&tx, 0);
        BOOST_CHECK_EQUAL(verdict(SpendOf(many), checker), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(checker.computations, 1);
    }
    // A wrong hash after a right one fails against the kept value.
    {
        CountingChecker checker(&tx, 0);
        const CScript script = CScript() << right0 << OP_CHECKTEMPLATEVERIFY << OP_DROP << wrong << OP_CHECKTEMPLATEVERIFY;
        BOOST_CHECK_EQUAL(verdict(SpendOf(script), checker), SCRIPT_ERR_CHECKTEMPLATEVERIFY);
        BOOST_CHECK_EQUAL(checker.computations, 1);
    }
    // A wrong hash first fails, and a right one after it passes.
    {
        CountingChecker checker(&tx, 0);
        BOOST_CHECK_EQUAL(verdict(SpendOf(CScript() << wrong << OP_CHECKTEMPLATEVERIFY), checker), SCRIPT_ERR_CHECKTEMPLATEVERIFY);
        BOOST_CHECK_EQUAL(verdict(SpendOf(CScript() << right0 << OP_CHECKTEMPLATEVERIFY), checker), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(checker.computations, 1);
    }
    // A checker for another input of the same transaction keeps its own
    // value: the hash of input 0 fails at input 1.
    {
        CountingChecker checker(&tx, 1);
        BOOST_CHECK_EQUAL(verdict(SpendOf(CScript() << right0 << OP_CHECKTEMPLATEVERIFY), checker), SCRIPT_ERR_CHECKTEMPLATEVERIFY);
        BOOST_CHECK_EQUAL(verdict(SpendOf(CScript() << right1 << OP_CHECKTEMPLATEVERIFY), checker), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(checker.computations, 1);
    }
    // An operand that is not 32 bytes fails before anything is computed.
    {
        CountingChecker checker(&tx, 0);
        BOOST_CHECK_EQUAL(verdict(SpendOf(CScript() << valtype(31, 0x01) << OP_CHECKTEMPLATEVERIFY), checker), SCRIPT_ERR_CHECKTEMPLATEVERIFY);
        BOOST_CHECK_EQUAL(checker.computations, 0);
        // The checker holds the same rule for a caller that is not the
        // opcode's handler.
        BOOST_CHECK(!checker.CheckTemplateVerify(valtype(33, 0x01)));
        BOOST_CHECK(!checker.CheckTemplateVerify(valtype(31, 0x01)));
        BOOST_CHECK_EQUAL(checker.computations, 0);
    }
}

// The verdict of a version 11 spend reads none of the flags of witness
// version 6 and does not wait for the flag of the restored opcodes.
BOOST_AUTO_TEST_CASE(the_verdict_reads_none_of_the_flags_of_witness_version_6)
{
    // OP_CHECKLOCKTIMEVERIFY asks for an input whose sequence is not final.
    CMutableTransaction mtx = SpendingTx();
    mtx.vin[0].nSequence = 0xfffffffe;
    const CTransaction tx(mtx);
    CKey owner;
    owner.MakeNewKey(true);
    const valtype ownerItem = KeyItem(owner);
    const valtype preimage(32, 0x07);

    // A branch, a hashlock with a length check, a timelock, a key-hash check
    // and an opcode of the restored set.
    CScript script;
    script << OP_IF
             << OP_SIZE << CScriptNum(32) << OP_EQUALVERIFY << OP_SHA256 << Sha256(preimage) << OP_EQUALVERIFY
             << Sha256(ownerItem) << OP_CHECKDILITHIUMKEYHASH << OP_1
           << OP_ELSE
             << CScriptNum(0) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << valtype(1, 0x0f) << valtype(1, 0x3c) << OP_AND << valtype(1, 0x0c) << OP_EQUAL
           << OP_ENDIF;
    const Spend claim = SpendOf(script, {SignV11(owner, script, tx), ownerItem, preimage, valtype(1, 0x01)});
    const Spend other = SpendOf(script, {valtype()});
    const Spend wrongPreimage = SpendOf(script, {SignV11(owner, script, tx), ownerItem, valtype(32, 0x08), valtype(1, 0x01)});

    const unsigned int v6 = SCRIPT_VERIFY_P2WSH_DILITHIUM | SCRIPT_VERIFY_DILITHIUM_KEYHASH | SCRIPT_VERIFY_V6_CONTROLFLOW;
    const unsigned int base = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CTV | SCRIPT_VERIFY_APO | SCRIPT_VERIFY_CSFS;
    for (unsigned int extra : {0u, v6, (unsigned int)SCRIPT_VERIFY_SCRIPT_RESTORE, v6 | SCRIPT_VERIFY_SCRIPT_RESTORE,
                               (unsigned int)SCRIPT_VERIFY_P2WSH_DILITHIUM, (unsigned int)SCRIPT_VERIFY_V6_CONTROLFLOW,
                               (unsigned int)SCRIPT_VERIFY_DILITHIUM_KEYHASH}) {
        BOOST_CHECK_MESSAGE(Verdict(claim, base | extra, tx) == SCRIPT_ERR_OK, "flags " << extra << ": got " << Name(Verdict(claim, base | extra, tx)));
        BOOST_CHECK_MESSAGE(Verdict(other, base | extra, tx) == SCRIPT_ERR_OK, "flags " << extra << ": got " << Name(Verdict(other, base | extra, tx)));
        BOOST_CHECK_MESSAGE(Verdict(wrongPreimage, base | extra, tx) == SCRIPT_ERR_EQUALVERIFY, "flags " << extra << ": got " << Name(Verdict(wrongPreimage, base | extra, tx)));
    }
}

// Over a set of spends and the eight combinations of the three deployments: a
// spend valid with a set of deployments active is valid with every subset of
// them, its count under a subset is no higher, and a spend relay's flags
// accept is one a block's flags accept.
BOOST_AUTO_TEST_CASE(a_spend_valid_with_a_deployment_more_is_valid_with_one_fewer)
{
    const CTransaction tx(SpendingTx());
    CKey owner, stranger;
    owner.MakeNewKey(true);
    stranger.MakeNewKey(true);
    const valtype ownerItem = KeyItem(owner);
    const CScript keyScript = SingleKeyScript(ownerItem);
    const valtype message(8, 0x44);
    const valtype csfsSig = SignHash(owner, Hash(message.begin(), message.end()));
    const CScript csfsScript = CScript() << OP_CHECKSIGFROMSTACK << Sha256(ownerItem) << OP_CHECKDILITHIUMKEYHASH << OP_1;
    const CScript ctvScript = CScript() << valtype(32, 0x99) << OP_CHECKTEMPLATEVERIFY << OP_DROP << OP_1;
    const valtype later(5, 0x03);

    const Spend spends[] = {
        SpendOf(keyScript, {SignV11(owner, keyScript, tx), ownerItem}),
        SpendOf(keyScript, {SignV11(stranger, keyScript, tx), KeyItem(stranger)}),
        SpendOf(keyScript, {}),
        SpendOf(csfsScript, {SignV11(owner, csfsScript, tx), ownerItem, csfsSig, message, ownerItem}),
        SpendOf(csfsScript, {SignV11(owner, csfsScript, tx), ownerItem, csfsSig, valtype(8, 0x45), ownerItem}),
        SpendOf(ctvScript, {}),
        SpendOf(CScript() << OP_1 << static_cast<opcodetype>(0xcc), {}),
        SpendOf(CScript() << OP_1, {}, 0x01),
        SpendOf(SingleKeyScript(later), {valtype(), later}),
        SpendOf(CScript() << OP_DUP << OP_1, {}),
        SpendOf(CScript() << OP_1, {}, 0xc0, valtype(2, 0x00)),
    };

    for (const Spend& s : spends) {
        bool valid[8];
        size_t count[8];
        for (int mask = 0; mask < 8; ++mask) {
            const unsigned int flags = BLOCK | Deployments(mask);
            valid[mask] = Verdict(s, flags, tx) == SCRIPT_ERR_OK;
            count[mask] = SigOps(s, flags);
            if (Verdict(s, flags | RELAY, tx) == SCRIPT_ERR_OK)
                BOOST_CHECK_MESSAGE(valid[mask], "combination " << mask << ": accepted at relay and refused in a block");
        }
        for (int larger = 0; larger < 8; ++larger) {
            for (int smaller = 0; smaller < 8; ++smaller) {
                if ((smaller & larger) != smaller)
                    continue;
                BOOST_CHECK_MESSAGE(!valid[larger] || valid[smaller],
                    "valid with combination " << larger << " and refused with its subset " << smaller);
                BOOST_CHECK_MESSAGE(count[smaller] <= count[larger],
                    "counts " << count[smaller] << " with combination " << smaller << " and " << count[larger] << " with " << larger);
            }
        }
    }
    // The set holds a spend of each outcome with the three active.
    BOOST_CHECK_EQUAL(Verdict(spends[0], ACTIVE, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Verdict(spends[1], ACTIVE, tx), SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
    BOOST_CHECK_EQUAL(Verdict(spends[3], ACTIVE, tx), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(SigOps(spends[3], ACTIVE), 2u);
    BOOST_CHECK_EQUAL(Verdict(spends[4], ACTIVE, tx), SCRIPT_ERR_CHECKSIGFROMSTACK);
    BOOST_CHECK_EQUAL(Verdict(spends[5], ACTIVE, tx), SCRIPT_ERR_CHECKTEMPLATEVERIFY);
    BOOST_CHECK_EQUAL(Verdict(spends[9], ACTIVE, tx), SCRIPT_ERR_DISALLOWED_OPCODE);
    BOOST_CHECK_EQUAL(Verdict(spends[10], ACTIVE, tx), SCRIPT_ERR_WITNESS_V11_TRAILER);
}

// The message of witness version 11 for a fixed transaction, one vector a
// hash type the version admits, against SignatureHash and against the format
// written out in this file. The message names the witness version, the
// sub-version and the key type, so it differs from the message of witness
// version 6 and between two key types.
BOOST_AUTO_TEST_CASE(the_message_vectors)
{
    const CTransaction tx(VectorTx());
    const CScript script = VectorScript();
    const PrecomputedTransactionData txdata(tx);

    for (const MessageVector& v : MESSAGE_VECTORS) {
        const uint256 node = SignatureHash(script, tx, VECTOR_INPUT, v.hashType, VECTOR_AMOUNT, SIGVERSION_WITNESS_V11, nullptr, 0x00);
        BOOST_CHECK_MESSAGE(RawHex(node) == v.message, "hash type " << v.hashType << ": SignatureHash gives " << RawHex(node));
        BOOST_CHECK_EQUAL(RawHex(V11Message(script, tx, VECTOR_INPUT, v.hashType, VECTOR_AMOUNT, 0x00)), v.message);
        // With the precomputed hashes of the transaction, and with the
        // default of the last argument.
        BOOST_CHECK(SignatureHash(script, tx, VECTOR_INPUT, v.hashType, VECTOR_AMOUNT, SIGVERSION_WITNESS_V11, &txdata, 0x00) == node);
        BOOST_CHECK(SignatureHash(script, tx, VECTOR_INPUT, v.hashType, VECTOR_AMOUNT, SIGVERSION_WITNESS_V11) == node);
        // Not the message of witness version 6, and not that of another key type.
        BOOST_CHECK(SignatureHash(script, tx, VECTOR_INPUT, v.hashType, VECTOR_AMOUNT, SIGVERSION_WITNESS_V0) != node);
        BOOST_CHECK(SignatureHash(script, tx, VECTOR_INPUT, v.hashType, VECTOR_AMOUNT, SIGVERSION_WITNESS_V11, nullptr, 0x01) != node);
    }
    BOOST_CHECK_EQUAL(RawHex(SignatureHash(script, tx, VECTOR_INPUT, SIGHASH_ALL, VECTOR_AMOUNT, SIGVERSION_WITNESS_V11, nullptr, 0x01)),
                      MESSAGE_VECTOR_OTHER_KEY_TYPE);

    // The new signature version has no anyprevout form: for those two bytes it
    // does not return what witness version 6 returns, with the three bytes or
    // without them.
    for (int b : {0x41, 0x42}) {
        const uint256 v11 = SignatureHash(script, tx, VECTOR_INPUT, b, VECTOR_AMOUNT, SIGVERSION_WITNESS_V11, nullptr, 0x00);
        BOOST_CHECK(v11 != SignatureHash(script, tx, VECTOR_INPUT, b, VECTOR_AMOUNT, SIGVERSION_WITNESS_V0));
        BOOST_CHECK(v11 == V11Message(script, tx, VECTOR_INPUT, b, VECTOR_AMOUNT, 0x00));
    }
}

// SignatureHash under the two signature versions that existed before witness
// version 11 returns, for every hash type below, what it returned before the
// new signature version was added: the six ordinary types, the two anyprevout
// types, the two values answered with a constant, with an output at the
// input's index and without one, and an input index outside the transaction.
BOOST_AUTO_TEST_CASE(sighash_of_the_existing_versions_is_unchanged)
{
    const CScript script = VectorScript();
    int rows = 0;
    for (const ExistingSighash& e : EXISTING_SIGHASHES) {
        CMutableTransaction mtx = VectorTx();
        mtx.vout.resize(e.outputs);
        const CTransaction tx(mtx);
        const PrecomputedTransactionData txdata(tx);
        const std::string where = std::to_string(e.outputs) + " outputs, hash type " + std::to_string(e.hashType);
        BOOST_CHECK_MESSAGE(RawHex(SignatureHash(script, tx, VECTOR_INPUT, e.hashType, VECTOR_AMOUNT, SIGVERSION_WITNESS_V0)) == e.witnessV0, where);
        BOOST_CHECK_MESSAGE(RawHex(SignatureHash(script, tx, VECTOR_INPUT, e.hashType, VECTOR_AMOUNT, SIGVERSION_BASE)) == e.base, where);
        // The key type argument is not read under either.
        BOOST_CHECK_MESSAGE(RawHex(SignatureHash(script, tx, VECTOR_INPUT, e.hashType, VECTOR_AMOUNT, SIGVERSION_WITNESS_V0, nullptr, 0x5a)) == e.witnessV0, where);
        BOOST_CHECK_MESSAGE(RawHex(SignatureHash(script, tx, VECTOR_INPUT, e.hashType, VECTOR_AMOUNT, SIGVERSION_BASE, nullptr, 0x5a)) == e.base, where);
        BOOST_CHECK_MESSAGE(RawHex(SignatureHash(script, tx, VECTOR_INPUT, e.hashType, VECTOR_AMOUNT, SIGVERSION_WITNESS_V0, &txdata)) == e.witnessV0, where);
        ++rows;
    }
    BOOST_CHECK_EQUAL(rows, 20);

    const CTransaction tx(VectorTx());
    BOOST_CHECK_EQUAL(RawHex(SignatureHash(script, tx, 5, SIGHASH_ALL, VECTOR_AMOUNT, SIGVERSION_WITNESS_V0)), UINT256_ONE_RAW);
    BOOST_CHECK_EQUAL(RawHex(SignatureHash(script, tx, 5, SIGHASH_ALL, VECTOR_AMOUNT, SIGVERSION_BASE)), UINT256_ONE_RAW);
}

BOOST_AUTO_TEST_SUITE_END()
