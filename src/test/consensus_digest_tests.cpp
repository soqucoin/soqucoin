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
#include "crypto/sha256.h"
#include "primitives/block.h"
#include "script/interpreter.h"
#include "script/script.h"
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

    // Pinned 2026-08-20, Apple clang 21 arm64 -O2, at the v2.0.0 freeze candidate.
    //
    // Moved from 0489e98d4d6465a42ef90a0d456c70804794b914cdd0e502ad0bbae3928a9fe7
    // for ONE reason, verified by isolation rather than assumed: AbsorbGlobalLimits
    // was added, bringing MAX_MONEY and the block limits under the digest for the
    // first time. Rebuilding with that call removed reproduced the old value
    // byte-for-byte on the new binary, which also proves the three other changes
    // in the same commit moved nothing in consensus:
    //   * -fno-strict-aliasing (bead eolo) perturbs no computed value;
    //   * the v2.0.0 version bump does not reach consensus;
    //   * adding SCRIPT_VERIFY_SCRIPT_RESTORE to relay policy (bead mxph) is
    //     policy, not consensus.
    const std::string expected =
        "5effd2ed86326721613bddbbe2002555b217e1008c27668557027dcacf6a7ce0";

    BOOST_CHECK_MESSAGE(digest.ToString() == expected,
        "consensus digest is " + digest.ToString() + ", expected " + expected +
        ". Identify which consensus input moved before updating the constant.");
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
