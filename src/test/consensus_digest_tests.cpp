// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// consensus_digest_tests.cpp — one hash over everything the consensus rules are
// made of. Bead v7xm, fork-risk class F4 (build-dependent consensus), and the
// tripwire for the eventual consensus FREEZE.
//
// WHY A SINGLE DIGEST. F4's proven instance was a strict-aliasing violation that
// made seed-derived PUBLIC data depend on the compiler's optimisation level: a
// chain split from a build flag, invisible to every functional test because both
// builds were internally consistent (bead nh6m). The only way to catch that
// class is to compare a build against ANOTHER BUILD, which needs a single value
// that summarises consensus and is cheap to compute. That is what this is.
//
// Two jobs, one artifact:
//
//   1. AS A CI TEST it is a freeze tripwire. Any change to a genesis hash, a
//      derived seed, a deployment parameter, an activation height, the subsidy
//      schedule, the PoW function or a script verdict moves the digest and fails
//      here. After the freeze that failure IS the review trigger; before it, the
//      constant is updated deliberately and the diff says what moved.
//
//   2. AS AN F4 HARNESS it is the thing you diff across builds. Compile at
//      -O0/-O1/-O2/-O3/-Os, and with each available compiler, run
//      `test_soqucoin --run_test=consensus_digest_tests` and compare the printed
//      digest. Equal digests are evidence of build-independence; a difference is
//      an nh6m-class defect and is a launch blocker.
//
// ⛔ THE DIGEST DELIBERATELY EXERCISES CODE, NOT JUST CONSTANTS. Reading
// chainparams fields back would only prove the compiler can copy integers. It
// therefore also runs scrypt (the PoW function, the heaviest arithmetic in the
// consensus path), HMAC-SHA256 through the real seed-derivation helper, the
// subsidy schedule, and the script interpreter over every witness version. Those
// are where a codegen difference could actually express itself.

#include "chainparams.h"
#include "amount.h"
#include "consensus/consensus.h"
#include "consensus/params.h"
#include "crypto/pat/logarithmic.h"
#include "crypto/sha256.h"
#include "primitives/block.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "soqucoin.h"
#include "streams.h"
#include "uint256.h"
#include "version.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(consensus_digest_tests, BasicTestingSetup)

namespace {

//! Accumulates every consensus-relevant value into one SHA256.
class DigestBuilder
{
public:
    void U64(uint64_t v)
    {
        // Fixed little-endian, so the digest cannot depend on host endianness or
        // on how the compiler lays out a struct.
        unsigned char b[8];
        for (int i = 0; i < 8; ++i) b[i] = (unsigned char)((v >> (8 * i)) & 0xff);
        m_h.Write(b, 8);
    }
    void I64(int64_t v)   { U64((uint64_t)v); }
    void Bytes(const unsigned char* p, size_t n) { m_h.Write(p, n); }
    void Hash(const uint256& h) { m_h.Write(h.begin(), 32); }
    void Str(const std::string& s) { U64(s.size()); m_h.Write((const unsigned char*)s.data(), s.size()); }

    uint256 Finalize()
    {
        uint256 out;
        m_h.Finalize(out.begin());
        return out;
    }

private:
    CSHA256 m_h;
};

//! Everything in a Consensus::Params that a validating node acts on.
void AbsorbConsensus(DigestBuilder& d, const Consensus::Params& c)
{
    d.Hash(c.hashGenesisBlock);
    d.I64(c.nSubsidyHalvingInterval);
    d.I64(c.BIP34Height);
    d.Hash(c.BIP34Hash);
    d.I64(c.BIP65Height);
    d.I64(c.BIP66Height);
    d.Hash(c.powLimit);
    d.I64(c.nPowTargetSpacing);
    d.I64(c.nPowTargetTimespan);
    d.I64(c.nRuleChangeActivationThreshold);
    d.I64(c.nMinerConfirmationWindow);
    d.I64(c.nCoinbaseMaturity);
    d.I64(c.nMaxReorgDepth);
    d.I64(c.dilithiumOnlyHeight);
    d.I64(c.nAuxpowChainId);
    d.I64(c.fStrictChainId ? 1 : 0);
    d.I64(c.nAuxpowStartHeight);
    d.I64(c.fAllowLegacyBlocks ? 1 : 0);
    d.I64(c.nHeightEffective);
    d.I64(c.fPowAllowMinDifficultyBlocks ? 1 : 0);
    d.I64(c.fPowNoRetargeting ? 1 : 0);
    d.I64(c.fDigishieldDifficultyCalculation ? 1 : 0);
    d.I64(c.fSimplifiedRewards ? 1 : 0);

    // The derived privacy seed. THIS is the field whose class of defect F4 exists
    // for: it is computed at startup by HKDF over the genesis hash, so it is both
    // public and code-derived, and the nh6m bug made exactly that kind of value
    // depend on the optimisation level.
    d.Bytes(c.latticeBPSeed.data(), c.latticeBPSeed.size());

    // Every deployment, every field. A version bit or an activation height moving
    // is a consensus change and must move the digest.
    for (int i = 0; i < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++i) {
        const Consensus::BIP9Deployment& dep = c.vDeployments[i];
        d.I64(dep.bit);
        d.I64(dep.nStartTime);
        d.I64(dep.nTimeout);
        d.I64(dep.nActivationHeight);
    }
}

//! Exercise the script interpreter over the full witness-version matrix, so a
//! codegen difference in verification shows up as a digest difference.
void AbsorbScriptVerdicts(DigestBuilder& d)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    CTxIn in;
    in.prevout = COutPoint(uint256S("0x3333333333333333333333333333333333333333333333333333333333333333"), 0);
    in.nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin.push_back(in);
    CTxOut o; o.nValue = 50 * COIN; o.scriptPubKey = CScript() << OP_TRUE;
    tx.vout.push_back(o);
    const CTransaction ctx(tx);

    const unsigned int flagSets[] = {
        SCRIPT_VERIFY_WITNESS,
        SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_USDSOQ,
        SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_BTCSOQ,
        SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_SOQUOBSCURA,
        SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2WSH_DILITHIUM,
        SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_PAT,
    };

    for (int version = 0; version <= 16; ++version) {
        for (size_t programLen : {size_t(20), size_t(32)}) {
            CScript spk;
            spk << (version == 0 ? OP_0 : CScript::EncodeOP_N(version));
            spk << std::vector<unsigned char>(programLen, 0x01);
            for (unsigned int flags : flagSets) {
                CScriptWitness w;
                w.stack.push_back(std::vector<unsigned char>(4, 0x00));
                w.stack.push_back(std::vector<unsigned char>(4, 0x11));
                ScriptError serr = SCRIPT_ERR_OK;
                TransactionSignatureChecker checker(&ctx, 0, 50 * COIN);
                const bool ok = VerifyScript(CScript(), spk, &w, flags, checker, &serr);
                d.I64(version);
                d.I64((int64_t)programLen);
                d.I64(flags);
                d.I64(ok ? 1 : 0);
                d.I64((int64_t)serr);
            }
        }
    }
}

//! A deterministic byte vector. ⛔ NEVER use GetRandHashVec() or anything else
//! random in this file: the digest has to be reproducible across builds forever,
//! which is the entire point of the instrument.
std::vector<unsigned char> FixedVec(size_t n, unsigned char seed)
{
    std::vector<unsigned char> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = (unsigned char)((seed + i * 31u) & 0xff);
    return v;
}

//! A VALID PAT full-mode script, built from fixed material.
//!
//! This is the one place the digest reaches real consensus cryptography, and it
//! matters more than the rest of this file put together: PAT is the only one of
//! these features ACTIVE FROM GENESIS on mainnet (SCRIPT_VERIFY_PAT), and its
//! proof construction is hash-tree arithmetic — exactly where an nh6m-class
//! codegen difference expresses itself.
//!
//! Stack layout, per interpreter.cpp's OP_CHECKPATAGG handler:
//!   <sigs...> <pks...> <msgs...> <count_le32> <proof> <agg_pk> <msg_root>
//!
//! The 32-byte "sigs" are not Dilithium signatures and are not meant to be. PAT
//! verifies no signatures by design; it proves an aggregation relation over the
//! supplied material. Fixed vectors are therefore a faithful input, and the
//! upstream PAT tests use random ones of exactly this shape.
bool BuildValidPatScript(uint32_t n, CScript& out)
{
    std::vector<std::vector<unsigned char> > sigs, pks, msgs;
    for (uint32_t i = 0; i < n; ++i) {
        sigs.push_back(FixedVec(32, (unsigned char)(0x10 + i)));
        pks.push_back(FixedVec(32, (unsigned char)(0x40 + i)));
        msgs.push_back(FixedVec(32, (unsigned char)(0x70 + i)));
    }

    std::vector<unsigned char> proof_data;
    if (!pat::CreateLogarithmicProof(sigs, pks, msgs, proof_data)) return false;

    pat::LogarithmicProof proof;
    if (!pat::ParseLogarithmicProof(proof_data, proof)) return false;

    const std::vector<unsigned char> agg_pk(proof.pk_agg.begin(), proof.pk_agg.end());
    const std::vector<unsigned char> msg_root(proof.msg_root.begin(), proof.msg_root.end());

    out = CScript();
    for (uint32_t i = 0; i < n; ++i) out << sigs[i];
    for (uint32_t i = 0; i < n; ++i) out << pks[i];
    for (uint32_t i = 0; i < n; ++i) out << msgs[i];
    std::vector<unsigned char> count(4);
    for (int i = 0; i < 4; ++i) count[i] = (unsigned char)((n >> (8 * i)) & 0xff);
    out << count;
    out << proof_data << agg_pk << msg_root;
    out << OP_CHECKPATAGG;
    return true;
}

//! ★★★ Custom-opcode and real-crypto verdicts. Bead 71z6.
//!
//! WHY THIS EXISTS. Until 2026-08-27 the script half of this digest absorbed
//! only witness-program dispatch: AbsorbScriptVerdicts builds an
//! `OP_N <program>` scriptPubKey and hands it a TWO-item, four-byte witness
//! stack. Every witness-dispatched feature demands more than that and returns a
//! shape error before reaching its verification math — PAT, for instance,
//! requires witness->stack.size() >= 4 (interpreter.cpp:1644) and otherwise
//! returns SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH. So the digest exercised the
//! dispatch and NOT ONE LINE of consensus cryptography, while its own header
//! claimed the interpreter was included because that is 'where a codegen
//! difference could actually express itself'.
//!
//! That was demonstrated rather than argued: the v4 dispatch was changed from
//! calling an unsound verifier to failing closed, a new ScriptError was added,
//! and this digest did not move.
//!
//! Nothing else covered the gap. Functional tests run on ONE build, so an
//! nh6m-class defect is invisible to them by construction. Differential
//! validation replays stagenet history through a SINGLE binary, so it compares
//! against history rather than against another build. This was the only
//! cross-build instrument, and it stopped at shape checks.
//!
//! ⛔ RULES FOR EXTENDING THIS FUNCTION:
//!   * Deterministic inputs only. No randomness, no clock, no host state.
//!   * Absorb (ok, serr) for BOTH the gated-off and gated-on flag state, so a
//!     change to gating moves the digest as well as a change to verification.
//!   * Adding anything here MOVES THE DIGEST. Re-pin deliberately and say what
//!     was added in the commit message.
//!   * New ScriptError values go at the END of the enum. This function absorbs
//!     the NUMERIC value, so inserting mid-enum renumbers every later error and
//!     moves the digest for no behavioural reason.
void AbsorbOpcodeVerdicts(DigestBuilder& d)
{
    BaseSignatureChecker checker;

    // -- PAT, the genesis-active path, with material that reaches the crypto --
    // Absorbed for several aggregation widths because the proof is a hash tree
    // and the tree shape changes with n.
    for (uint32_t n : {uint32_t(1), uint32_t(2), uint32_t(3), uint32_t(4)}) {
        CScript patScript;
        const bool built = BuildValidPatScript(n, patScript);
        d.I64(built ? 1 : 0);
        d.I64(n);
        if (!built) continue;

        // The proof bytes themselves are consensus-visible output of the PAT
        // construction, so absorb the script directly as well as the verdict.
        // If a codegen difference changes the hash tree, this catches it even if
        // the verdict happens to stay the same.
        d.U64(patScript.size());
        d.Bytes((const unsigned char*)patScript.data(), patScript.size());

        for (unsigned int flags : {(unsigned int)0, (unsigned int)SCRIPT_VERIFY_PAT}) {
            std::vector<std::vector<unsigned char> > stack;
            ScriptError serr = SCRIPT_ERR_OK;
            const bool ok = EvalScript(stack, patScript, flags, checker,
                                       SIGVERSION_BASE, &serr);
            d.I64(flags);
            d.I64(ok ? 1 : 0);
            d.I64((int64_t)serr);
            d.U64(stack.size());
            for (const std::vector<unsigned char>& item : stack) {
                d.U64(item.size());
                if (!item.empty()) d.Bytes(item.data(), item.size());
            }
        }
    }

    // -- A tampered PAT proof must be rejected, and the REASON is absorbed --
    // A codegen difference that broke the aggregation check would most likely
    // show up as this flipping to accept.
    {
        CScript patScript;
        if (BuildValidPatScript(3, patScript)) {
            // Rebuild with one witness pk replaced, header left honest.
            std::vector<std::vector<unsigned char> > sigs, pks, msgs;
            for (uint32_t i = 0; i < 3; ++i) {
                sigs.push_back(FixedVec(32, (unsigned char)(0x10 + i)));
                pks.push_back(FixedVec(32, (unsigned char)(0x40 + i)));
                msgs.push_back(FixedVec(32, (unsigned char)(0x70 + i)));
            }
            std::vector<unsigned char> proof_data;
            if (pat::CreateLogarithmicProof(sigs, pks, msgs, proof_data)) {
                pat::LogarithmicProof proof;
                if (pat::ParseLogarithmicProof(proof_data, proof)) {
                    const std::vector<unsigned char> agg_pk(proof.pk_agg.begin(), proof.pk_agg.end());
                    const std::vector<unsigned char> msg_root(proof.msg_root.begin(), proof.msg_root.end());
                    pks[1] = FixedVec(32, 0xEE);  // tamper

                    CScript bad;
                    for (uint32_t i = 0; i < 3; ++i) bad << sigs[i];
                    for (uint32_t i = 0; i < 3; ++i) bad << pks[i];
                    for (uint32_t i = 0; i < 3; ++i) bad << msgs[i];
                    std::vector<unsigned char> count(4, 0); count[0] = 3;
                    bad << count << proof_data << agg_pk << msg_root;
                    bad << OP_CHECKPATAGG;

                    std::vector<std::vector<unsigned char> > stack;
                    ScriptError serr = SCRIPT_ERR_OK;
                    const bool ok = EvalScript(stack, bad, SCRIPT_VERIFY_PAT, checker,
                                               SIGVERSION_BASE, &serr);
                    d.I64(ok ? 1 : 0);
                    d.I64((int64_t)serr);
                }
            }
        }
    }

    // -- Every other custom opcode, in both gate states --
    //
    // These carry well-SHAPED but deliberately invalid payloads. That is not a
    // weakness: nh6m lived in seed-derived statement-matrix construction, i.e.
    // in deserialisation and derivation, which runs before any accept decision.
    // Exercising the parse-and-derive path with fixed bytes is what catches that
    // class. Where a payload cannot be made valid deterministically without a
    // prover, the recorded verdict is a reject, and a codegen change that moves
    // WHICH reject fires still moves the digest.
    struct OpCase {
        const char* name;
        opcodetype op;
        unsigned int gate;
        int stack_items;
        size_t item_size;
    };
    const OpCase opCases[] = {
        { "checkpatagg_malformed",  OP_CHECKPATAGG,           SCRIPT_VERIFY_PAT,          4,   32 },
        { "checkfoldproof",         OP_CHECKFOLDPROOF,        SCRIPT_VERIFY_LATTICEFOLD,  4, 1280 },
        { "soquobscura_rangeproof", OP_SOQUOBSCURA_RANGEPROOF, SCRIPT_VERIFY_SOQUOBSCURA, 3,  256 },
        { "usdsoq_mint",            OP_USDSOQ_MINT,           SCRIPT_VERIFY_USDSOQ,       4,   64 },
        { "usdsoq_burn",            OP_USDSOQ_BURN,           SCRIPT_VERIFY_USDSOQ,       4,   64 },
        { "usdsoq_freeze",          OP_USDSOQ_FREEZE,         SCRIPT_VERIFY_USDSOQ,       4,   64 },
        { "usdsoq_rotate",          OP_USDSOQ_ROTATE,         SCRIPT_VERIFY_USDSOQ,       4,   64 },
        { "checkdilithiumkeyhash",  OP_CHECKDILITHIUMKEYHASH, SCRIPT_VERIFY_DILITHIUM_KEYHASH, 3, 64 },
    };

    for (const OpCase& c : opCases) {
        d.Str(c.name);
        for (unsigned int flags : {(unsigned int)0, c.gate}) {
            CScript script = CScript() << c.op;
            std::vector<std::vector<unsigned char> > stack;
            for (int i = 0; i < c.stack_items; ++i) {
                stack.push_back(FixedVec(c.item_size, (unsigned char)(0x20 + i)));
            }
            ScriptError serr = SCRIPT_ERR_OK;
            const bool ok = EvalScript(stack, script, flags, checker,
                                       SIGVERSION_BASE, &serr);
            d.I64(flags);
            d.I64(ok ? 1 : 0);
            d.I64((int64_t)serr);
        }
    }

    // -- Satoshi Restoration arithmetic guards --
    // Pure integer arithmetic with fixed operands: the cheapest possible probe
    // for an arithmetic codegen difference, and it exercises the division and
    // modulo guards that carry their own script errors.
    {
        struct ArithCase { const char* name; int64_t a; int64_t b; opcodetype op; };
        const ArithCase arith[] = {
            { "div_normal",   1000,  7, OP_DIV },
            { "div_by_zero",  1000,  0, OP_DIV },
            { "mod_normal",   1000,  7, OP_MOD },
            { "mod_by_zero",  1000,  0, OP_MOD },
            { "div_negative", -1000, 7, OP_DIV },
            { "mod_negative", -1000, 7, OP_MOD },
            { "mul_large",    1 << 30, 1 << 20, OP_MUL },
            { "lshift",       1,      31, OP_LSHIFT },
            { "rshift",       1 << 30, 15, OP_RSHIFT },
        };
        for (const ArithCase& a : arith) {
            d.Str(a.name);
            CScript script = CScript() << CScriptNum(a.a) << CScriptNum(a.b) << a.op;
            std::vector<std::vector<unsigned char> > stack;
            ScriptError serr = SCRIPT_ERR_OK;
            const bool ok = EvalScript(stack, script, SCRIPT_VERIFY_SCRIPT_RESTORE,
                                       checker, SIGVERSION_BASE, &serr);
            d.I64(ok ? 1 : 0);
            d.I64((int64_t)serr);
            d.U64(stack.size());
            for (const std::vector<unsigned char>& item : stack) {
                d.U64(item.size());
                if (!item.empty()) d.Bytes(item.data(), item.size());
            }
        }
    }
}

//! Network-independent consensus constants. These live in headers rather than
//! chainparams, so nothing above would notice them changing — and MAX_MONEY in
//! particular is consensus-critical (MoneyRange gates every value check) and was
//! not covered by this digest until 2026-08-20.
void AbsorbGlobalLimits(DigestBuilder& d)
{
    d.I64(MAX_MONEY);
    d.I64(COIN);
    d.I64(MAX_BLOCK_WEIGHT);
    d.I64(MAX_BLOCK_SERIALIZED_SIZE);
    d.I64(MAX_BLOCK_BASE_SIZE);
    d.I64(MAX_BLOCK_SIGOPS_COST);
    d.I64(WITNESS_SCALE_FACTOR);
}

uint256 ComputeConsensusDigest()
{
    DigestBuilder d;
    AbsorbGlobalLimits(d);

    for (const std::string& net : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                   CBaseChainParams::REGTEST, CBaseChainParams::STAGENET}) {
        SelectParams(net);
        d.Str(net);

        // Every consensus tier, not just the base struct: each network indexes a
        // height tree and blocks above a cutover validate against a different one.
        for (int h : {0, 1, 2, 9, 10, 11, 19, 20, 21, 99, 100, 101, 1000, 1000000}) {
            d.I64(h);
            AbsorbConsensus(d, Params().GetConsensus(h));
        }

        // The genesis block itself, serialised, plus its hash and its PoW hash.
        // GetPoWHash runs scrypt, which is by far the heaviest arithmetic on the
        // consensus path and the most likely place for a codegen difference to
        // become visible.
        const CBlock& genesis = Params().GenesisBlock();
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << genesis;
        d.Bytes((const unsigned char*)ss.data(), ss.size());
        d.Hash(genesis.GetHash());
        d.Hash(genesis.hashMerkleRoot);
        d.Hash(genesis.GetPoWHash());

        // The emission schedule, sampled across every regime boundary that
        // matters. 47B total supply is a locked figure; a subsidy that moves by
        // one satoshi at one height is a chain split.
        const uint256 prevHash = uint256S(
            "0x4444444444444444444444444444444444444444444444444444444444444444");
        for (int h : {0, 1, 2, 99, 100, 1000, 100000, 144000, 500000, 1000000,
                      2000000, 5000000, 10000000}) {
            d.I64(h);
            d.I64(GetSoqucoinBlockSubsidy(h, Params().GetConsensus(h), prevHash));
        }
    }

    AbsorbScriptVerdicts(d);
    AbsorbOpcodeVerdicts(d);

    SelectParams(CBaseChainParams::MAIN);
    return d.Finalize();
}

} // namespace

// ---------------------------------------------------------------------------
// ⛔ IF THIS FAILS, SOMETHING ABOUT CONSENSUS CHANGED. That is not always wrong,
// but it is never incidental. Work out WHICH input moved before touching the
// constant, and update the constant in the same commit as the change that caused
// it, so the diff carries the explanation.
//
// Regenerate with:
//   src/test/test_soqucoin --run_test=consensus_digest_tests --log_level=message
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(consensus_digest_is_pinned)
{
    const uint256 digest = ComputeConsensusDigest();
    BOOST_TEST_MESSAGE("CONSENSUS DIGEST: " << digest.ToString());

    // Pinned 2026-08-26, Apple clang 21 arm64 -O2, at the FC4 candidate.
    //
    // Moved from 5effd2ed86326721613bddbbe2002555b217e1008c27668557027dcacf6a7ce0
    // for exactly the consensus inputs FC4 changed, each individually intended:
    //   * MAX_MONEY 10B -> 20B (bead iwzf; AbsorbGlobalLimits input). 40B was
    //     tried first and moved the digest to c346a6b6...; the CompressAmount
    //     codec bound then reduced the value to 20B, so the 40B digest never
    //     shipped anywhere.
    //   * testnet CSV moved off the inherited 2016/2017 BIP9 window to
    //     ALWAYS_ACTIVE (per-network deployment inputs).
    //   * witness v10 gained its own gated dispatch failing closed under
    //     USDSOQ+SOQUOBSCURA (bead jzg0; script-verdict matrix inputs, where
    //     the flag sets cover it).
    // The regtest BIP9 lever fix in the same commit mutates nothing at
    // construction time and therefore contributes nothing here.
    //
    // Prior pin history: moved from 0489e98d... on 2026-08-20 when
    // AbsorbGlobalLimits first brought MAX_MONEY and the block limits under
    // the digest (verified by isolation at the time).
    //
    // Moved from f830d7d6... on 2026-08-27 when AbsorbOpcodeVerdicts was added
    // (bead 71z6). This was a COVERAGE change, not a rule change: no consensus
    // rule moved, the digest simply started measuring things it had never
    // measured. Before this, the script half of the digest absorbed only
    // witness-program DISPATCH — AbsorbScriptVerdicts hands every witness
    // version a two-item, four-byte witness stack, and every feature bails on
    // its shape check before reaching any verification math (PAT requires
    // >= 4 items, interpreter.cpp:1644). So the digest exercised no consensus
    // cryptography at all, while claiming the interpreter was included because
    // that is where a codegen difference expresses itself.
    //
    // Proven, not assumed: changing the v4 dispatch from calling an unsound
    // verifier to failing closed, plus adding a ScriptError, did NOT move the
    // old digest. The new function is guarded by
    // opcode_coverage_actually_reaches_pat_crypto below, so the coverage cannot
    // silently regress to shape-rejection again.
    const std::string expected =
        "df60b54de75e72cf1cd7387cb0b1bc01191c1bccd0a1e7644927aa423750401b";

    BOOST_CHECK_MESSAGE(digest.ToString() == expected,
        "consensus digest is " + digest.ToString() + ", expected " + expected +
        ". Identify which consensus input moved before updating the constant.");
}

// ---------------------------------------------------------------------------
// ★★★ THE COVERAGE GUARD. Bead 71z6.
//
// A digest can be green, stable and cross-build identical while measuring
// nothing that matters — which is exactly the state this file was in until
// 2026-08-27. Pinning the constant does not detect that; only asserting that the
// instrument reaches real cryptography does.
//
// This test therefore makes two claims about AbsorbOpcodeVerdicts' inputs:
//   1. A VALID PAT proof can be built from fixed material, so the digest is not
//      silently absorbing a construction failure.
//   2. That proof is ACCEPTED with SCRIPT_VERIFY_PAT set — meaning execution got
//      past every shape check and through the aggregation arithmetic — and a
//      tampered one is REJECTED, meaning the check is load-bearing rather than
//      vacuous.
//
// PAT is the case that matters most: it is the only one of these features active
// from genesis on mainnet, and its proof is hash-tree arithmetic, the same shape
// of code as the nh6m defect.
//
// ⛔ If this fails, do not re-pin the digest. The digest has stopped measuring
// consensus cryptography and the pin is meaningless until it does again.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(opcode_coverage_actually_reaches_pat_crypto)
{
    BaseSignatureChecker checker;

    for (uint32_t n : {uint32_t(1), uint32_t(2), uint32_t(3), uint32_t(4)}) {
        CScript patScript;
        BOOST_REQUIRE_MESSAGE(BuildValidPatScript(n, patScript),
            "could not build a valid PAT proof at n=" + std::to_string(n) +
            "; AbsorbOpcodeVerdicts is absorbing a construction failure, so the "
            "digest is not measuring PAT at all");

        std::vector<std::vector<unsigned char> > stack;
        ScriptError serr = SCRIPT_ERR_OK;
        const bool ok = EvalScript(stack, patScript, SCRIPT_VERIFY_PAT, checker,
                                   SIGVERSION_BASE, &serr);
        BOOST_CHECK_MESSAGE(ok,
            "a VALID PAT proof at n=" + std::to_string(n) + " was rejected with "
            "error " + std::to_string((int)serr) + ". Either PAT is broken, or the "
            "digest's PAT input stopped being valid and is now recording a shape "
            "rejection instead of the aggregation arithmetic — which is the exact "
            "blindness bead 71z6 fixed.");
    }

    // The check must be load-bearing: tamper one witness pk, leave the header
    // honest, and require rejection. A verifier that accepts this is measuring
    // nothing, and a digest over it would be stable and worthless.
    {
        std::vector<std::vector<unsigned char> > sigs, pks, msgs;
        for (uint32_t i = 0; i < 3; ++i) {
            sigs.push_back(FixedVec(32, (unsigned char)(0x10 + i)));
            pks.push_back(FixedVec(32, (unsigned char)(0x40 + i)));
            msgs.push_back(FixedVec(32, (unsigned char)(0x70 + i)));
        }
        std::vector<unsigned char> proof_data;
        BOOST_REQUIRE(pat::CreateLogarithmicProof(sigs, pks, msgs, proof_data));
        pat::LogarithmicProof proof;
        BOOST_REQUIRE(pat::ParseLogarithmicProof(proof_data, proof));
        const std::vector<unsigned char> agg_pk(proof.pk_agg.begin(), proof.pk_agg.end());
        const std::vector<unsigned char> msg_root(proof.msg_root.begin(), proof.msg_root.end());

        pks[1] = FixedVec(32, 0xEE);

        CScript bad;
        for (uint32_t i = 0; i < 3; ++i) bad << sigs[i];
        for (uint32_t i = 0; i < 3; ++i) bad << pks[i];
        for (uint32_t i = 0; i < 3; ++i) bad << msgs[i];
        std::vector<unsigned char> count(4, 0); count[0] = 3;
        bad << count << proof_data << agg_pk << msg_root;
                    bad << OP_CHECKPATAGG;

        std::vector<std::vector<unsigned char> > stack;
        ScriptError serr = SCRIPT_ERR_OK;
        const bool ok = EvalScript(stack, bad, SCRIPT_VERIFY_PAT, checker,
                                   SIGVERSION_BASE, &serr);
        BOOST_CHECK_MESSAGE(!ok,
            "a TAMPERED PAT proof was accepted. The aggregation check is not "
            "load-bearing, so absorbing its verdict into the consensus digest "
            "measures nothing.");
    }
}

// Determinism within a single build. A digest that varies run to run would mean
// something in the consensus path reads uninitialised memory or unpinned global
// state, and would also make the cross-build comparison meaningless.
BOOST_AUTO_TEST_CASE(consensus_digest_is_stable_within_a_build)
{
    const uint256 a = ComputeConsensusDigest();
    const uint256 b = ComputeConsensusDigest();
    const uint256 c = ComputeConsensusDigest();
    BOOST_CHECK_MESSAGE(a == b && b == c,
        "the consensus digest changed between runs in the SAME binary: " +
        a.ToString() + " / " + b.ToString() + " / " + c.ToString() +
        ". Something on the consensus path depends on uninitialised memory or on "
        "mutable global state, which makes any cross-build comparison worthless");
}

BOOST_AUTO_TEST_SUITE_END()
