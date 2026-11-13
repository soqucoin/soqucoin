// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Fuzz target v6_witness_script: a witness v6 spend through VerifyScript and
// its witnessScript through EvalScript, with the six covenant deployment flags
// (P2WSH_DILITHIUM, DILITHIUM_KEYHASH, V6_CONTROLFLOW, CTV, APO, CSFS) set and
// clear, over the flags every block sets and over the flags relay sets.
//
// Input layout. Every byte string decodes; bytes past the end read as zero.
//   [0]       bits 0..5  the six deployment flags, in the order above
//             bits 6..7  the mode of the stand-in for the ML-DSA-44
//                        verification that ends the transaction checker's
//                        CheckSig: 0 the node's own verification, 1 it answers
//                        false, 2 and 3 it answers true
//   [1]       bits 0..1  the witness: 0 items, script, trailer; 1 none at all;
//                        2 no trailer; 3 the program differs from the script
//   [2..5]    nVersion of the spending transaction, little-endian
//   [6..9]    nLockTime
//   [10..13]  nSequence of the input
//   [14]      n, the number of satisfaction items
//   n times   a two-byte little-endian length, then that many bytes
//   the rest  the witnessScript
//
// The mode governs that one step and nothing else. OP_CHECKDILITHIUMKEYHASH
// reaches it through checker.CheckSig, after the handler's own checks (the
// item count and sizes, the key hash, the hashtype) and after CheckSig refuses
// an empty signature, so a keyhash check can fail in modes 2 and 3.
// OP_CHECKSIGFROMSTACK does not ask the checker: it verifies with
// CPubKey::Verify in every mode, and the target neither replaces nor records
// that verification.
//
// What is checked for each input, beyond the absence of a memory error. A
// failed check prints its name and aborts.
//   determinism   VerifyScript returns the same verdict and error twice, and
//                 the same verdict without an error pointer; EvalScript leaves
//                 the same stack twice.
//   verdict       an acceptance carries SCRIPT_ERR_OK and a refusal an error.
//   dormant       with P2WSH_DILITHIUM clear the spend verifies with
//                 SCRIPT_ERR_OK, whatever the witness and the other flags.
//   prescan       a witnessScript that does not parse, or that holds a byte
//                 the opcode set refuses, is refused with that byte's error in
//                 every flag state in which the v6 branch runs.
//   dispatch      for every other witnessScript, VerifyScript's verdict is
//                 EvalScript's on the satisfaction items followed by the rule
//                 that exactly one true item remains.
//   relay         a spend that verifies under the relay flags verifies under
//                 the block flags with the same deployment flags.
//   signature     a signature check is a call the node makes to the checker's
//                 CheckSig, and a verification is the step the mode stands in
//                 for; OP_CHECKSIGFROMSTACK makes neither. With
//                 P2WSH_DILITHIUM or DILITHIUM_KEYHASH clear there is no check
//                 and no verification. A check that answers false is the last
//                 one asked for and the spend is refused with
//                 SCRIPT_ERR_CHECKDILITHIUMKEYHASH, and as many checks answer
//                 true as verifications do. So an accepted spend passed every
//                 check it asked for, and in mode 1 it asked for none. With
//                 DILITHIUM_KEYHASH set, an accepted witnessScript without a
//                 conditional made one verification for each
//                 OP_CHECKDILITHIUMKEYHASH it holds.
//   keyhash       with DILITHIUM_KEYHASH set, in an accepted witnessScript whose
//                 every OP_CHECKDILITHIUMKEYHASH directly follows a push of 32
//                 bytes, each signature was checked for a key whose SHA-256 is
//                 that push, in script order.
//
// The opcode set is not written here. It is read from the binary once, with
// one-opcode scripts in the state with all six flags set, and four things
// are required of it then:
//   anchor        the witnessScript OP_1 is accepted.
//   handler       every byte the set admits changes the stack or fails in its
//                 handler when EvalScript runs it; none is skipped.
//   branch        a refused byte is refused inside a branch that is not taken.
//   flags         a refused byte is refused with the other five flags clear and
//                 under the relay flags.
// v6_witness_script_opcode_set_tests pins the members of the set.
//
// A rule that refuses a witness whatever its script (a bound on the items) is
// found with a script that drops every item; such a witness must be refused
// and is left out of the dispatch comparison.
//
// Run one input:    FUZZ=v6_witness_script test/fuzz/fuzz < input
// Trace one input:  FUZZ_V6_TRACE=1 FUZZ=v6_witness_script test/fuzz/fuzz < input
// With an engine:   Fuzz.cpp leaves out its main when __LIBFUZZER__ is defined,
//                   for an engine that supplies one (libFuzzer: -fsanitize=fuzzer).
//                   FUZZ selects the target; a maximum input length of 16384
//                   covers a witnessScript of MAX_SCRIPT_SIZE.
// Seeds:            test/fuzz/corpus/v6_witness_script_*, written by
//                   test/fuzz/gen_v6_witness_script_corpus.py

#include <amount.h>
#include <crypto/sha256.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/standard.h>
#include <test/fuzz/fuzz.h>
#include <uint256.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

// Defined in script/interpreter.cpp and declared in no header.
bool CastToBool(const std::vector<unsigned char>& vch);

namespace
{
typedef std::vector<unsigned char> valtype;

const unsigned int SIX_FLAGS[6] = {
    SCRIPT_VERIFY_P2WSH_DILITHIUM,
    SCRIPT_VERIFY_DILITHIUM_KEYHASH,
    SCRIPT_VERIFY_V6_CONTROLFLOW,
    SCRIPT_VERIFY_CTV,
    SCRIPT_VERIFY_APO,
    SCRIPT_VERIFY_CSFS,
};
const unsigned int ALL_SIX = SCRIPT_VERIFY_P2WSH_DILITHIUM | SCRIPT_VERIFY_DILITHIUM_KEYHASH |
                             SCRIPT_VERIFY_V6_CONTROLFLOW | SCRIPT_VERIFY_CTV |
                             SCRIPT_VERIFY_APO | SCRIPT_VERIFY_CSFS;

//! What ConnectBlock sets for every block besides the deployment flags, as far
//! as the v6 branch reads it.
const unsigned int BLOCK_BASE = MANDATORY_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_SCRIPT_RESTORE;
//! What the mempool sets besides the deployment flags.
const unsigned int RELAY_BASE = STANDARD_SCRIPT_VERIFY_FLAGS;
const unsigned int ACTIVE = BLOCK_BASE | ALL_SIX;

enum SigMode { SIG_REAL = 0,
               SIG_REFUSE = 1,
               SIG_ACCEPT = 2 };

[[noreturn]] void Fail(const char* check, const std::string& detail)
{
    std::fprintf(stderr, "v6_witness_script: check '%s' failed: %s\n", check, detail.c_str());
    std::abort();
}

std::string Hex(unsigned int v)
{
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%x", v);
    return buf;
}

std::string Describe(bool ok, ScriptError err)
{
    return std::string(ok ? "accepted" : "refused") + " (error " + std::to_string(static_cast<int>(err)) + ", " + ScriptErrorString(err) + ")";
}

uint256 Sha256(const valtype& data)
{
    // An empty vector may hold a null pointer; hash from a real one, wide
    // enough for the block-sized step CSHA256::Write takes from it.
    static const unsigned char none[64] = {0};
    uint256 hash;
    CSHA256().Write(data.empty() ? none : data.data(), data.size()).Finalize(hash.begin());
    return hash;
}

//! What the checker saw during one VerifyScript.
struct SignatureRecord {
    //! What CheckSig answered the node, one entry for each call, in the order made.
    std::vector<bool> answers;
    //! SHA-256 of the public key of each verification, in the order made.
    std::vector<uint256> keys;
    //! How many of those verifications answered true.
    size_t nVerified = 0;

    bool Empty() const { return answers.empty() && keys.empty(); }
    bool operator==(const SignatureRecord& o) const { return answers == o.answers && keys == o.keys && nVerified == o.nVerified; }
};

//! The transaction checker of the node with the ML-DSA-44 verification that
//! ends CheckSig replaceable, and with every CheckSig call and every
//! verification recorded. Everything before the verification (the hashtype
//! byte, the signature hash, the locktime, sequence and template checks) is
//! the node's.
class CountingChecker : public TransactionSignatureChecker
{
    const SigMode mode;
    mutable SignatureRecord record;

protected:
    bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint256& sighash) const override
    {
        record.keys.push_back(Sha256(valtype(pubkey.begin(), pubkey.end())));
        const bool fValid = mode == SIG_ACCEPT || (mode == SIG_REAL && TransactionSignatureChecker::VerifySignature(vchSig, pubkey, sighash));
        if (fValid) record.nVerified++;
        return fValid;
    }

public:
    CountingChecker(const CTransaction* tx, const CAmount& amount, SigMode modeIn)
        : TransactionSignatureChecker(tx, 0, amount), mode(modeIn) {}
    bool CheckSig(const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override
    {
        const bool fAnswer = TransactionSignatureChecker::CheckSig(vchSig, vchPubKey, scriptCode, sigversion);
        record.answers.push_back(fAnswer);
        return fAnswer;
    }
    const SignatureRecord& Record() const { return record; }
};

CScript V6Program(const uint256& program)
{
    return CScript() << OP_6 << valtype(program.begin(), program.end());
}

struct Verdict {
    bool ok;
    ScriptError err;
    SignatureRecord sigs;
    bool operator==(const Verdict& o) const { return ok == o.ok && err == o.err && sigs == o.sigs; }
};

//! The spend under test: a fixed one-input transaction shape whose version,
//! locktime and sequence come from the input, and the witness as given.
struct Spend {
    CTransaction tx;
    CAmount amount;
    SigMode sigMode;
    CScript scriptPubKey;
    CScriptWitness witness;
    bool fNoWitness;

    Verdict Verify(unsigned int flags) const
    {
        const CScriptWitness* w = fNoWitness ? nullptr : &witness;
        const CountingChecker first(&tx, amount, sigMode);
        ScriptError err = SCRIPT_ERR_UNKNOWN_ERROR;
        const bool ok = VerifyScript(CScript(), scriptPubKey, w, flags, first, &err);
        const Verdict v = {ok, err, first.Record()};

        const CountingChecker second(&tx, amount, sigMode);
        ScriptError err2 = SCRIPT_ERR_UNKNOWN_ERROR;
        const bool ok2 = VerifyScript(CScript(), scriptPubKey, w, flags, second, &err2);
        const Verdict v2 = {ok2, err2, second.Record()};
        if (!(v == v2))
            Fail("determinism", "VerifyScript under flags " + Hex(flags) + ": " + Describe(ok, err) + " then " + Describe(ok2, err2));

        const CountingChecker third(&tx, amount, sigMode);
        if (VerifyScript(CScript(), scriptPubKey, w, flags, third, nullptr) != ok)
            Fail("determinism", "VerifyScript under flags " + Hex(flags) + " without an error pointer disagrees with " + Describe(ok, err));

        if ((ok && err != SCRIPT_ERR_OK) || (!ok && err == SCRIPT_ERR_OK))
            Fail("verdict", "VerifyScript under flags " + Hex(flags) + " returned " + Describe(ok, err));
        return v;
    }
};

Spend MakeSpend(int32_t nVersion, uint32_t nLockTime, uint32_t nSequence, SigMode sigMode,
                const uint256& program, const std::vector<valtype>& stack, bool fNoWitness)
{
    CMutableTransaction mtx;
    mtx.nVersion = nVersion;
    mtx.nLockTime = nLockTime;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("0000000000000000000000000000000000000000000000000000000000000001"), 0);
    mtx.vin[0].nSequence = nSequence;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = COIN;
    mtx.vout[0].scriptPubKey = CScript() << OP_1 << valtype(32, 0x11);

    Spend s = {CTransaction(mtx), 50 * COIN, sigMode, V6Program(program), CScriptWitness(), fNoWitness};
    s.witness.stack = stack;
    return s;
}

//! A spend of `script` with `items`, in the witness shape the node documents:
//! the items, the script, a one-byte trailer.
Spend PlainSpend(const valtype& script, const std::vector<valtype>& items, SigMode sigMode = SIG_REFUSE)
{
    std::vector<valtype> stack(items);
    stack.push_back(script);
    stack.push_back(valtype(1, 0x00));
    return MakeSpend(2, 0, 0, sigMode, Sha256(script), stack, false);
}

struct Evaluation {
    bool ok;
    ScriptError err;
    std::vector<valtype> stack;
};

Evaluation Evaluate(const Spend& spend, const std::vector<valtype>& items, const CScript& script, unsigned int flags)
{
    Evaluation e;
    e.stack = items;
    e.err = SCRIPT_ERR_UNKNOWN_ERROR;
    const CountingChecker first(&spend.tx, spend.amount, spend.sigMode);
    e.ok = EvalScript(e.stack, script, flags, first, SIGVERSION_WITNESS_V0, &e.err);

    std::vector<valtype> again(items);
    ScriptError err2 = SCRIPT_ERR_UNKNOWN_ERROR;
    const CountingChecker second(&spend.tx, spend.amount, spend.sigMode);
    const bool ok2 = EvalScript(again, script, flags, second, SIGVERSION_WITNESS_V0, &err2);
    if (ok2 != e.ok || err2 != e.err || again != e.stack)
        Fail("determinism", "EvalScript under flags " + Hex(flags) + ": " + Describe(e.ok, e.err) + " then " + Describe(ok2, err2));
    return e;
}

//! A script of the one opcode `b`, with the data a push opcode needs.
valtype OneOpcode(unsigned int b)
{
    valtype s(1, static_cast<unsigned char>(b));
    if (b >= 0x01 && b <= 0x4b) {
        s.insert(s.end(), b, 0x00);
    } else if (b == OP_PUSHDATA1 || b == OP_PUSHDATA2 || b == OP_PUSHDATA4) {
        const size_t nLengthBytes = (b == OP_PUSHDATA1) ? 1 : (b == OP_PUSHDATA2) ? 2 : 4;
        s.push_back(0x01);
        s.insert(s.end(), nLengthBytes - 1, 0x00);
        s.push_back(0x00);
    }
    return s;
}

bool IsRefusal(ScriptError err)
{
    return err == SCRIPT_ERR_BAD_OPCODE || err == SCRIPT_ERR_DISALLOWED_OPCODE;
}

//! The opcode set of the v6 branch, as the binary under test holds it.
struct OpcodeSet {
    //! SCRIPT_ERR_OK for a byte the set admits, else the error it is refused with.
    ScriptError refusal[256];
    //! The error of a witnessScript that does not parse.
    ScriptError unparseable;

    bool Admits(unsigned int b) const { return refusal[b] == SCRIPT_ERR_OK; }

    OpcodeSet()
    {
        const std::vector<valtype> none;
        // anchor: the v6 branch runs in the state the set is read in, and
        // accepts the shortest script that leaves one true item.
        const Verdict one = PlainSpend(valtype(1, OP_1), none).Verify(ACTIVE);
        if (!one.ok)
            Fail("anchor", "the witnessScript OP_1 is " + Describe(one.ok, one.err));
        for (unsigned int b = 0; b < 256; b++) {
            const Verdict v = PlainSpend(OneOpcode(b), none).Verify(ACTIVE);
            refusal[b] = (!v.ok && IsRefusal(v.err)) ? v.err : SCRIPT_ERR_OK;
        }
        const Verdict cut = PlainSpend(valtype(1, OP_PUSHDATA1), none).Verify(ACTIVE);
        if (cut.ok)
            Fail("prescan", "a witnessScript that ends inside a push is " + Describe(cut.ok, cut.err));
        unparseable = cut.err;

        const bool fBranchProbe = Admits(OP_0) && Admits(OP_1) && Admits(OP_IF) && Admits(OP_ENDIF);
        for (unsigned int b = 0; b < 256; b++) {
            const valtype one = OneOpcode(b);
            if (Admits(b)) {
                // handler: on an empty stack a byte without a handler leaves the
                // stack empty and EvalScript answers EVAL_FALSE.
                const Spend spend = PlainSpend(one, none);
                const Evaluation e = Evaluate(spend, none, CScript(one.begin(), one.end()), ACTIVE);
                if (!e.ok && e.err == SCRIPT_ERR_EVAL_FALSE && e.stack.empty())
                    Fail("handler", "byte " + Hex(b) + " is admitted by the opcode set and EvalScript skips it");
                continue;
            }
            if (fBranchProbe) {
                valtype inBranch;
                inBranch.push_back(OP_0);
                inBranch.push_back(OP_IF);
                inBranch.insert(inBranch.end(), one.begin(), one.end());
                inBranch.push_back(OP_ENDIF);
                inBranch.push_back(OP_1);
                const Verdict v = PlainSpend(inBranch, none).Verify(ACTIVE);
                if (v.ok || v.err != refusal[b])
                    Fail("branch", "byte " + Hex(b) + " inside a branch that is not taken is " + Describe(v.ok, v.err));
            }
            const unsigned int others[2] = {BLOCK_BASE | SCRIPT_VERIFY_P2WSH_DILITHIUM, RELAY_BASE | ALL_SIX};
            for (unsigned int i = 0; i < 2; i++) {
                const Verdict v = PlainSpend(one, none).Verify(others[i]);
                if (v.ok || v.err != refusal[b])
                    Fail("flags", "byte " + Hex(b) + " under flags " + Hex(others[i]) + " is " + Describe(v.ok, v.err));
            }
        }
    }
};

//! A witnessScript as the checks need it.
struct ScriptShape {
    //! What the pre-scan does with it, by the opcode set: SCRIPT_ERR_OK when it passes.
    ScriptError refusal;
    unsigned int nKeyhashOps;
    //! It holds OP_IF, OP_NOTIF, OP_ELSE or OP_ENDIF.
    bool fConditional;
    //! Every OP_CHECKDILITHIUMKEYHASH directly follows a push of 32 bytes.
    bool fKeyhashesPushed;
    //! Those pushes, in script order.
    std::vector<uint256> keyhashes;
};

ScriptShape Shape(const OpcodeSet& set, const CScript& script)
{
    ScriptShape s = {SCRIPT_ERR_OK, 0, false, true, std::vector<uint256>()};
    CScript::const_iterator pc = script.begin();
    opcodetype op;
    valtype data;
    valtype previous;
    bool fPreviousPush32 = false;
    while (pc < script.end()) {
        if (!script.GetOp(pc, op, data)) {
            s.refusal = set.unparseable;
            return s;
        }
        if (!set.Admits(op)) {
            s.refusal = set.refusal[op];
            return s;
        }
        if (op == OP_CHECKDILITHIUMKEYHASH) {
            s.nKeyhashOps++;
            if (fPreviousPush32)
                s.keyhashes.push_back(uint256(previous));
            else
                s.fKeyhashesPushed = false;
        }
        if (op == OP_IF || op == OP_NOTIF || op == OP_ELSE || op == OP_ENDIF) s.fConditional = true;
        fPreviousPush32 = (op <= OP_PUSHDATA4 && data.size() == 32);
        previous = data;
    }
    return s;
}

//! Whether `part` is `whole` with elements left out, the order kept.
bool IsSubsequence(const std::vector<uint256>& part, const std::vector<uint256>& whole)
{
    size_t matched = 0;
    for (size_t i = 0; i < whole.size() && matched < part.size(); i++)
        if (whole[i] == part[matched]) matched++;
    return matched == part.size();
}

//! Reads the input; past its end every byte is zero.
class Reader
{
    const uint8_t* p;
    size_t left;

public:
    Reader(const uint8_t* data, size_t size) : p(data), left(size) {}
    uint8_t Byte()
    {
        if (left == 0) return 0;
        --left;
        return *p++;
    }
    uint32_t Le32()
    {
        uint32_t v = 0;
        for (int i = 0; i < 4; i++) v |= static_cast<uint32_t>(Byte()) << (8 * i);
        return v;
    }
    valtype Bytes(size_t n)
    {
        if (n > left) n = left;
        valtype v(p, p + n);
        p += n;
        left -= n;
        return v;
    }
    valtype Rest() { return Bytes(left); }
};

//! The signature checks that hold of a verdict in every flag state and every
//! mode. The node asks the checker for a signature in one place, the
//! OP_CHECKDILITHIUMKEYHASH handler. The handler runs with P2WSH_DILITHIUM and
//! DILITHIUM_KEYHASH set, in a branch that is taken, and fails the script when
//! CheckSig answers false.
void CheckSignatures(unsigned int flags, const Verdict& v, const std::string& got)
{
    const unsigned int handler = SCRIPT_VERIFY_P2WSH_DILITHIUM | SCRIPT_VERIFY_DILITHIUM_KEYHASH;
    if ((flags & handler) != handler && !v.sigs.Empty())
        Fail("signature", got + ", a signature was checked with P2WSH_DILITHIUM or DILITHIUM_KEYHASH clear");

    const std::vector<bool>& answers = v.sigs.answers;
    size_t nTrue = 0;
    for (size_t i = 0; i < answers.size(); i++) {
        if (answers[i]) {
            nTrue++;
            continue;
        }
        if (v.ok)
            Fail("signature", got + ", accepted with a signature check that answered false");
        if (i + 1 != answers.size() || v.err != SCRIPT_ERR_CHECKDILITHIUMKEYHASH)
            Fail("signature", got + ", a signature check answered false and the script went on");
    }
    // CheckSig answers true exactly when its verification does. In mode 1 no
    // verification does, so there an accepted spend asked for no check.
    if (nTrue != v.sigs.nVerified)
        Fail("signature", got + ", " + std::to_string(nTrue) + " signature checks answered true and " + std::to_string(v.sigs.nVerified) + " verifications did");
}

//! The checks on one flag state. Returns the verdict of VerifyScript.
Verdict CheckState(const OpcodeSet& set, const Spend& spend, unsigned int flags, std::string* trace)
{
    const Verdict v = spend.Verify(flags);
    const std::string got = "flags " + Hex(flags) + ": " + Describe(v.ok, v.err);
    CheckSignatures(flags, v, got);

    if (!(flags & SCRIPT_VERIFY_P2WSH_DILITHIUM)) {
        if (!v.ok || v.err != SCRIPT_ERR_OK)
            Fail("dormant", got);
        if (trace) *trace += " dormant";
        return v;
    }

    // The witness as the branch reads it: the last item is the trailer, the one
    // before it the witnessScript, the rest the satisfaction items.
    const std::vector<valtype>& stack = spend.witness.stack;
    if (spend.fNoWitness || stack.size() < 2) {
        if (v.ok || v.err != SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH)
            Fail("dispatch", got + ", a witness of fewer than two items");
        if (trace) *trace += " short-witness";
        return v;
    }
    const valtype& scriptBytes = stack[stack.size() - 2];
    const std::vector<valtype> items(stack.begin(), stack.end() - 2);

    // A witness refused whatever its script.
    if (set.Admits(OP_DROP) && set.Admits(OP_1)) {
        valtype dropAll(items.size(), static_cast<unsigned char>(OP_DROP));
        dropAll.push_back(OP_1);
        const Verdict bound = PlainSpend(dropAll, items).Verify(ACTIVE);
        if (!bound.ok) {
            if (v.ok)
                Fail("dispatch", got + ", the same items are refused under a script that drops them all: " + Describe(bound.ok, bound.err));
            if (trace) *trace += " witness-rule";
            return v;
        }
    }

    const CScript scriptPubKey = V6Program(Sha256(scriptBytes));
    if (scriptPubKey != spend.scriptPubKey) {
        if (v.ok || v.err != SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH)
            Fail("dispatch", got + ", the program is not the hash of the witnessScript");
        if (trace) *trace += " program-mismatch";
        return v;
    }
    if (scriptBytes.size() > static_cast<size_t>(MAX_SCRIPT_SIZE)) {
        if (v.ok || v.err != SCRIPT_ERR_SCRIPT_SIZE)
            Fail("dispatch", got + ", a witnessScript above MAX_SCRIPT_SIZE");
        if (trace) *trace += " script-size";
        return v;
    }

    const CScript script(scriptBytes.begin(), scriptBytes.end());
    const ScriptShape shape = Shape(set, script);
    if (shape.refusal != SCRIPT_ERR_OK) {
        if (v.ok || v.err != shape.refusal)
            Fail("prescan", got + ", expected " + ScriptErrorString(shape.refusal));
        if (!v.sigs.Empty())
            Fail("signature", got + ", a signature was checked for a refused witnessScript");
        if (trace) *trace += " prescan-refused";
        return v;
    }

    const Evaluation e = Evaluate(spend, items, script, flags);
    const bool fClean = e.ok && e.stack.size() == 1 && CastToBool(e.stack.back());
    const ScriptError expected = !e.ok ? e.err : (fClean ? SCRIPT_ERR_OK : SCRIPT_ERR_EVAL_FALSE);
    if (v.ok != fClean || v.err != expected)
        Fail("dispatch", got + ", EvalScript " + Describe(e.ok, e.err) + " with " + std::to_string(e.stack.size()) + " stack items");

    if (flags & SCRIPT_VERIFY_DILITHIUM_KEYHASH) {
        const std::vector<uint256>& keys = v.sigs.keys;
        if (keys.size() > shape.nKeyhashOps)
            Fail("signature", got + ", more signatures checked than keyhash opcodes");
        if (v.ok && !shape.fConditional && keys.size() != shape.nKeyhashOps)
            Fail("signature", got + ", " + std::to_string(keys.size()) + " signatures checked for " + std::to_string(shape.nKeyhashOps) + " keyhash opcodes");
        // Each keyhash opcode runs once at most and in script order, so the keys
        // checked hash to the pushes that precede the opcodes that ran.
        if (v.ok && shape.fKeyhashesPushed) {
            if (shape.fConditional ? !IsSubsequence(keys, shape.keyhashes) : keys != shape.keyhashes)
                Fail("keyhash", got + ", a signature was checked for a key that does not hash to the keyhash pushed before its opcode");
        }
    }
    if (trace) *trace += v.ok ? " executed-accepted" : " executed-refused";
    return v;
}

} // namespace

void v6_witness_script(fuzzer::FuzzBuffer& buffer) noexcept
{
    static const OpcodeSet set;
    static const bool fTrace = std::getenv("FUZZ_V6_TRACE") != nullptr;

    Reader in(buffer.data(), buffer.size());
    const uint8_t flagByte = in.Byte();
    const uint8_t shape = in.Byte() & 3;
    const int32_t nVersion = static_cast<int32_t>(in.Le32());
    const uint32_t nLockTime = in.Le32();
    const uint32_t nSequence = in.Le32();
    const unsigned int nItems = in.Byte();
    std::vector<valtype> stack;
    for (unsigned int i = 0; i < nItems; i++) {
        const size_t lo = in.Byte();
        const size_t hi = in.Byte();
        stack.push_back(in.Bytes(lo | (hi << 8)));
    }
    const valtype script = in.Rest();

    unsigned int six = 0;
    for (int i = 0; i < 6; i++)
        if (flagByte & (1u << i)) six |= SIX_FLAGS[i];
    const unsigned int modeBits = flagByte >> 6;
    const SigMode sigMode = modeBits == 0 ? SIG_REAL : (modeBits == 1 ? SIG_REFUSE : SIG_ACCEPT);

    uint256 program = Sha256(script);
    stack.push_back(script);
    if (shape != 2) stack.push_back(valtype(1, 0x00));
    if (shape == 3) *program.begin() ^= 0x01;
    const Spend spend = MakeSpend(nVersion, nLockTime, nSequence, sigMode, program, stack, shape == 1);

    std::string trace;
    std::string* t = fTrace ? &trace : nullptr;

    if (t) *t += "block:";
    const Verdict block = CheckState(set, spend, BLOCK_BASE | six, t);
    if (t) *t += " relay:";
    const Verdict relay = CheckState(set, spend, RELAY_BASE | six, t);
    if (relay.ok && !block.ok)
        Fail("relay", "accepted under the relay flags, under the block flags " + Describe(block.ok, block.err));

    // The state mainnet is in, and the input's state with the v6 branch dormant.
    const unsigned int dormant[3] = {BLOCK_BASE, BLOCK_BASE | (six & ~SCRIPT_VERIFY_P2WSH_DILITHIUM), RELAY_BASE | (six & ~SCRIPT_VERIFY_P2WSH_DILITHIUM)};
    for (int i = 0; i < 3; i++)
        CheckState(set, spend, dormant[i], nullptr);

    if (fTrace) {
        std::fprintf(stderr, "v6_witness_script: six=%s sig=%u shape=%u items=%u script=%u | %s | block %s, relay %s\n",
            Hex(six).c_str(), static_cast<unsigned int>(sigMode), static_cast<unsigned int>(shape), nItems,
            static_cast<unsigned int>(script.size()), trace.c_str(),
            Describe(block.ok, block.err).c_str(), Describe(relay.ok, relay.err).c_str());
    }
}
