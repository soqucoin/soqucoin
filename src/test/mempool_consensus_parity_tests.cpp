// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// mempool_consensus_parity_tests.cpp — relay policy and consensus must agree
// about what a transaction means. Bead v7xm, fork-risk class F7.
//
// WHY THIS CLASS MATTERS, from the incident that named it. On stagenet, live bug
// daf9fd85: the mempool verified a v7 USDSOQ input WITHOUT
// SCRIPT_VERIFY_USDSOQ, so a mis-signed send (wrong scriptCode, NULLFAIL) was
// accepted and relayed. It then sat in the mempool poisoning every block
// template that included it, and the pool mined empty coinbase-only blocks until
// it expired. Nothing was stolen; the chain simply stopped carrying
// transactions. That is what a policy set LOOSER than consensus buys you.
//
// The two directions are not symmetric, and naming them is most of the analysis:
//
//   policy LOOSER than consensus  -> accept-then-reject. A relayed transaction
//                                    cannot be mined. Block templates stall.
//                                    This is the dangerous direction.
//   policy STRICTER than consensus -> a transaction that is valid in a block can
//                                    never reach a miner through the network.
//                                    The feature is unusable, but the chain is
//                                    safe. Annoying, not dangerous.
//
// So the invariant to hold is: EVERY script flag ConnectBlock sets must also be
// set by the mempool. Extra strictness in the mempool is permitted.
//
// THAT INVARIANT NOW HOLDS. It did not until 2026-08-20: SCRIPT_VERIFY_SCRIPT_RESTORE
// was set unconditionally by ConnectBlock and never by the mempool, and because
// the restored opcodes are NO-OPS rather than errors without it, the same script
// had two truth values. Fixed by adding the flag to STANDARD_SCRIPT_VERIFY_FLAGS
// (bead mxph). These tests now pin the fix; the history is kept in the comments
// because the reasoning is what stops it being undone.

#include "chainparams.h"
#include "coins.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "miner.h"
#include "policy/policy.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/standard.h"
#include "txmempool.h"
#include "utilstrencodings.h"
#include "validation.h"

#include "test/dilithium_chain_setup.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(mempool_consensus_parity_tests, BasicTestingSetup)

namespace {

//! Evaluate and return the resulting stack, rendered for comparison. The error
//! code alone is not enough: an opcode that becomes a NO-OP still "succeeds",
//! while leaving a different stack and therefore a different truth value.
std::string EvalStack(const CScript& script, unsigned int flags)
{
    std::vector<std::vector<unsigned char> > stack;
    ScriptError serr = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;
    const bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serr);
    std::string out = ok ? "ok[" : (std::string("ERR(") + ScriptErrorString(serr) + ")[");
    for (size_t i = 0; i < stack.size(); ++i) {
        if (i) out += ",";
        out += HexStr(stack[i]);
    }
    return out + "]";
}

} // namespace

// ---------------------------------------------------------------------------
// The unconditional half of ConnectBlock's flag set. These are set for every
// block at every height with no deployment gate, so the mempool must carry all
// of them or it is permanently looser than consensus.
//
// Five of the six come from STANDARD_SCRIPT_VERIFY_FLAGS and are fine. The sixth
// is asserted separately below because it does not.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(mempool_carries_the_unconditional_consensus_flags)
{
    struct Row { unsigned int flag; const char* name; };
    const Row unconditional[] = {
        { SCRIPT_VERIFY_DERSIG,                "SCRIPT_VERIFY_DERSIG" },
        { SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,   "SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY" },
        { SCRIPT_VERIFY_WITNESS,               "SCRIPT_VERIFY_WITNESS" },
        { SCRIPT_VERIFY_NULLDUMMY,             "SCRIPT_VERIFY_NULLDUMMY" },
        // CSV is BIP9-gated in ConnectBlock but ALWAYS_ACTIVE on every network,
        // so in practice it is unconditional too.
        { SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,   "SCRIPT_VERIFY_CHECKSEQUENCEVERIFY" },
        // Added to the policy base on 2026-08-20; see the dedicated case below.
        { SCRIPT_VERIFY_SCRIPT_RESTORE,        "SCRIPT_VERIFY_SCRIPT_RESTORE" },
    };

    for (const Row& r : unconditional) {
        BOOST_CHECK_MESSAGE((STANDARD_SCRIPT_VERIFY_FLAGS & r.flag) != 0,
            std::string(r.name) + " is set unconditionally by ConnectBlock but is absent from "
            "STANDARD_SCRIPT_VERIFY_FLAGS. The mempool would then verify more leniently than "
            "consensus, which is the accept-then-reject direction: relayed transactions that "
            "cannot be mined, and block templates that stall. That is live bug daf9fd85");
    }
}

// P2SH is the whole of MANDATORY_SCRIPT_VERIFY_FLAGS, so it is worth pinning
// that STANDARD really is built on top of it rather than beside it.
BOOST_AUTO_TEST_CASE(standard_flags_are_a_superset_of_mandatory)
{
    BOOST_CHECK_MESSAGE(
        (STANDARD_SCRIPT_VERIFY_FLAGS & MANDATORY_SCRIPT_VERIFY_FLAGS) == MANDATORY_SCRIPT_VERIFY_FLAGS,
        "STANDARD_SCRIPT_VERIFY_FLAGS must contain every mandatory flag");
}

// The deployment-gated flags are computed in two places (ATMP and ConnectBlock)
// from the same predicate at the same height, so they agree by construction:
// NextBlockDeploymentScriptFlags, which ATMP calls for its sigop count and its
// script checks, is DeploymentActiveAtHeight(tipHeight + 1, ...) and
// ConnectBlock uses DeploymentActiveAtHeight(pindex->nHeight, ...) for the block
// being connected, which is that same height. PAT and LatticeFold use
// VersionBitsState against the tip on both sides.
//
// What is NOT guaranteed by construction is that a NEW deployment gets added to
// both lists. This pins the pairing so a flag added to only one side is visible:
// if a deployment ever gates a flag in ConnectBlock and nothing gates it in the
// mempool, the tx is accept-then-reject.
BOOST_AUTO_TEST_CASE(deployment_gated_flags_are_paired)
{
    // Every SCRIPT_VERIFY_* flag that a DEPLOYMENT gates in ConnectBlock. Keeping
    // this list here means adding a deployment-gated flag to validation.cpp
    // without adding it to BOTH paths shows up as a stale list rather than as a
    // stalled block template three weeks later.
    const unsigned int deploymentGated =
        SCRIPT_VERIFY_CTV | SCRIPT_VERIFY_APO | SCRIPT_VERIFY_CSFS |
        SCRIPT_VERIFY_P2WSH_DILITHIUM | SCRIPT_VERIFY_DILITHIUM_KEYHASH |
        SCRIPT_VERIFY_V6_CONTROLFLOW | SCRIPT_VERIFY_PAT | SCRIPT_VERIFY_LATTICEFOLD |
        SCRIPT_VERIFY_SOQUOBSCURA | SCRIPT_VERIFY_USDSOQ | SCRIPT_VERIFY_BTCSOQ;

    // None of them may be baked into STANDARD: they must be OR-ed in per height,
    // or the mempool would enforce a dormant rule and reject transactions that
    // consensus accepts.
    BOOST_CHECK_MESSAGE((STANDARD_SCRIPT_VERIFY_FLAGS & deploymentGated) == 0,
        "a deployment-gated flag has been baked into STANDARD_SCRIPT_VERIFY_FLAGS. Those must "
        "be OR-ed in per height on both paths, or the mempool enforces a rule consensus has "
        "not activated and rejects transactions that are perfectly valid in a block");
}

// ---------------------------------------------------------------------------
// ⛔ THE ONE REAL DIVERGENCE. ConnectBlock sets SCRIPT_VERIFY_SCRIPT_RESTORE
// UNCONDITIONALLY ("Satoshi script restoration: always-active on Soqucoin,
// genesis-active, no BIP9 gate needed"). STANDARD_SCRIPT_VERIFY_FLAGS does not
// contain it, and MANDATORY_SCRIPT_VERIFY_FLAGS is only SCRIPT_VERIFY_P2SH.
//
// policy.h lists it under SOQ-COV-012 as an intentional omission, grouped with
// SCRIPT_VERIFY_CTV, APO and CSFS, on the reasoning that adding these "would
// cause the mempool to enforce covenant rules on relay, which is premature
// before Phase 2 Halborn audit".
//
// THAT REASONING IS SOUND FOR THE OTHER THREE AND BACKWARDS FOR THIS ONE, and
// the difference is what the flag does. CTV, APO and CSFS ADD ENFORCEMENT: with
// the flag, previously-permitted scripts start being restricted, and consensus
// keeps them dormant on mainnet so policy and consensus agree at OFF/OFF.
// SCRIPT_RESTORE ADDS CAPABILITY: with the flag, OP_MUL and friends execute;
// without it they are disabled. And consensus has it ON from genesis with no
// dormancy to fall back on. So instead of a temporary OFF/OFF it produces a
// permanent ON-in-consensus / OFF-in-policy split, from block 1.
//
// The direction is the SAFE one (policy stricter), so this is a feature that
// cannot be used rather than a chain hazard, and it is the exact shape of bead
// 845h: consensus-valid, never relayable. Pinned rather than fixed, because
// making the restored opcodes relay-standard is a product decision.
// ---------------------------------------------------------------------------
// THE DIVERGENCE THAT WAS HERE, NOW CLOSED (bead mxph).
//
// ConnectBlock sets SCRIPT_VERIFY_SCRIPT_RESTORE unconditionally ("Satoshi
// script restoration: always-active on Soqucoin, genesis-active, no BIP9 gate
// needed"). STANDARD_SCRIPT_VERIFY_FLAGS did not contain it, and
// MANDATORY_SCRIPT_VERIFY_FLAGS is only SCRIPT_VERIFY_P2SH.
//
// policy.h SOQ-COV-012 had listed it as an intentional omission alongside
// SCRIPT_VERIFY_CTV, APO and CSFS. That reasoning was sound for those three and
// backwards for this one. CTV, APO and CSFS ADD ENFORCEMENT and consensus keeps
// them NOT_SCHEDULED on mainnet, so policy and consensus agree at off/off until
// activation. SCRIPT_RESTORE ADDS CAPABILITY and consensus has it on from
// genesis, so the same omission produced a permanent split instead.
//
// And it was not the safe direction, which is why it had to be fixed rather
// than documented: without the flag the restored opcodes are silent NO-OPS, not
// errors, so a script SUCCEEDED on both paths while leaving a different stack.
// `0 7 OP_MUL` left FALSE under consensus and TRUE under relay, so a
// transaction spending such an output would be accepted and relayed by every
// node and could never be mined. That is accept-then-reject, the
// template-stalling failure of live bug daf9fd85.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(script_restore_is_carried_by_relay_policy)
{
    BOOST_CHECK_MESSAGE((STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_SCRIPT_RESTORE) != 0,
        "SCRIPT_VERIFY_SCRIPT_RESTORE has left STANDARD_SCRIPT_VERIFY_FLAGS. ConnectBlock "
        "still sets it for every block, so removing it from relay policy reopens the "
        "accept-then-reject split described above. If the consensus side became gated "
        "instead, update both together");
}

// The property that actually matters: a script means the same thing to the
// mempool and to a block. Same cases that used to diverge.
BOOST_AUTO_TEST_CASE(restored_opcodes_mean_the_same_thing_on_both_paths)
{
    struct Case { const char* name; CScript script; };
    std::vector<Case> cases;
    { CScript s; s << CScriptNum(6)  << CScriptNum(7) << OP_MUL; cases.push_back({"OP_MUL", s}); }
    { CScript s; s << CScriptNum(84) << CScriptNum(2) << OP_DIV; cases.push_back({"OP_DIV", s}); }
    { CScript s; s << CScriptNum(85) << CScriptNum(4) << OP_MOD; cases.push_back({"OP_MOD", s}); }
    { CScript s; s << std::vector<unsigned char>{0xaa} << std::vector<unsigned char>{0xbb} << OP_CAT;
      cases.push_back({"OP_CAT", s}); }
    // The one that used to flip a truth value: 0 * 7 = 0 is FALSE under
    // consensus, while skipping the multiply leaves a top element of 0x07,
    // which is TRUE.
    { CScript s; s << CScriptNum(0) << CScriptNum(7) << OP_MUL; cases.push_back({"0 7 OP_MUL", s}); }

    // What ConnectBlock uses for these opcodes, versus what the mempool uses.
    const unsigned int consensusFlags = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_SCRIPT_RESTORE;
    const unsigned int mempoolFlags   = STANDARD_SCRIPT_VERIFY_FLAGS;

    for (const Case& c : cases) {
        const std::string consensusView = EvalStack(c.script, consensusFlags);
        const std::string mempoolView   = EvalStack(c.script, mempoolFlags);
        BOOST_TEST_MESSAGE(std::string(c.name) + ": consensus " + consensusView +
                           "  mempool " + mempoolView);
        BOOST_CHECK_MESSAGE(consensusView == mempoolView,
            std::string(c.name) + " evaluates differently at relay and in a block: consensus " +
            consensusView + " versus mempool " + mempoolView + ". A transaction spending such "
            "an output relays and cannot be mined, which stalls block templates");
    }
}

// Guard on the mechanism rather than the outcome. The fix works because the
// flag is in the policy base; if the restored opcodes ever start erroring
// without it instead of no-opping, the failure mode changes character and this
// file's reasoning needs revisiting.
BOOST_AUTO_TEST_CASE(restored_opcodes_are_still_noops_when_the_flag_is_absent)
{
    CScript mul;
    mul << CScriptNum(6) << CScriptNum(7) << OP_MUL;

    BOOST_CHECK_MESSAGE(EvalStack(mul, SCRIPT_VERIFY_SCRIPT_RESTORE) == "ok[2a]",
        "OP_MUL must execute when the flag is set");
    BOOST_CHECK_MESSAGE(EvalStack(mul, 0) == "ok[06,07]",
        "without the flag OP_MUL is expected to be a silent NO-OP, leaving its operands. If it "
        "now ERRORS instead, that is a safer shape and the policy fix is belt-and-braces rather "
        "than load-bearing; re-read bead mxph before relying on either");
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// The sigop count. The mempool prices a transaction's sigops once, at
// acceptance, and the miner sums the recorded figures against
// MAX_BLOCK_SIGOPS_COST; ConnectBlock charges the same transaction with the
// block's flags. The two figures must agree for the miner's budget to be the
// block's. The witness count of a v6 input reads three deployment-gated flags
// (P2WSH_DILITHIUM for the program, DILITHIUM_KEYHASH and CSFS for the opcodes
// it charges), so the mempool prices with the deployment flags of the next
// block, the same flags its script check reads.
//
// Driven through a real regtest chain, where the v6 deployments are active
// from height 0: a v6 output locked by the key-hash 2-of-2 is funded in a mined
// block and spent through the mempool, and the figure the mempool records and
// the figure the template carries are compared with the block's charge. The
// second case moves the key-hash deployment to one block above the tip, where
// the tip's flags and the next block's flags price the spend differently.
// ---------------------------------------------------------------------------
namespace {

//! The key-hash 2-of-2 (both keys the fixture's coinbase key) funded in a mined
//! regtest block, and its spend, signed and not yet relayed.
struct SigopParitySetup : public DilithiumChainSetup {
    typedef std::vector<unsigned char> valtype;

    CScript ws;
    CMutableTransaction S;

    SigopParitySetup()
    {
        // <kh> CHECKDILITHIUMKEYHASH <kh> CHECKDILITHIUMKEYHASH 1
        valtype kh(32);
        CSHA256().Write(coinbasePkBytes.data(), coinbasePkBytes.size()).Finalize(kh.data());
        ws << kh << OP_CHECKDILITHIUMKEYHASH << kh << OP_CHECKDILITHIUMKEYHASH << OP_1;
        uint256 program;
        CSHA256().Write(ws.data(), ws.size()).Finalize(program.begin());
        const CScript v6Spk = CScript() << OP_6 << valtype(program.begin(), program.end());

        // F: coinbase[0] to the v6 output, mined.
        const CAmount cbValue = coinbaseTxns[0].vout[0].nValue;
        const CAmount FEE = COIN;
        BOOST_REQUIRE(cbValue > 3 * FEE);
        CMutableTransaction F;
        F.nVersion = 2;
        F.vin.push_back(CTxIn(COutPoint(coinbaseTxns[0].GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        F.vout.push_back(CTxOut(cbValue - FEE, v6Spk));
        SignInput(F, 0, coinbaseSpk, cbValue);
        const CBlock bF = CreateAndProcessBlock(std::vector<CMutableTransaction>(1, F), coinbaseSpk);
        BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == bF.GetHash(), "the funding block must connect");

        // S: spends F:0 back to the coinbase key, both signatures over the
        // witnessScript as scriptCode. Witness: [sig, pubkey, sig, pubkey]
        // [witnessScript] [0x00-prefixed trailer].
        const CAmount amount = cbValue - FEE;
        S.nVersion = 2;
        S.vin.push_back(CTxIn(COutPoint(F.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        S.vout.push_back(CTxOut(amount - FEE, coinbaseSpk));
        const uint256 sighash = SignatureHash(ws, CTransaction(S), 0, SIGHASH_ALL, amount,
                                              SIGVERSION_WITNESS_V0, nullptr);
        valtype sig;
        BOOST_REQUIRE(coinbaseKey.Sign(sighash, sig));
        sig.push_back((unsigned char)SIGHASH_ALL);
        CScriptWitness w;
        w.stack.push_back(sig);
        w.stack.push_back(coinbasePkBytes);
        w.stack.push_back(sig);
        w.stack.push_back(coinbasePkBytes);
        w.stack.push_back(valtype(ws.begin(), ws.end()));
        w.stack.push_back(PrefixedPubkey(coinbasePkBytes));
        S.vin[0].scriptWitness = w;
    }

    //! What a block at nHeight charges for S, with the flags ConnectBlock sets at
    //! that height that the counter reads: P2SH and WITNESS, and the three
    //! deployment-gated flags from DeploymentActiveAtHeight at that height.
    int64_t BlockChargeAt(int nHeight)
    {
        LOCK(cs_main);
        const Consensus::Params& cons = Params().GetConsensus(nHeight);
        unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
        if (Consensus::DeploymentActiveAtHeight(nHeight, cons, Consensus::DEPLOYMENT_P2WSH_DILITHIUM))
            flags |= SCRIPT_VERIFY_P2WSH_DILITHIUM;
        if (Consensus::DeploymentActiveAtHeight(nHeight, cons, Consensus::DEPLOYMENT_DILITHIUM_KEYHASH))
            flags |= SCRIPT_VERIFY_DILITHIUM_KEYHASH;
        if (Consensus::DeploymentActiveAtHeight(nHeight, cons, Consensus::DEPLOYMENT_CSFS))
            flags |= SCRIPT_VERIFY_CSFS;
        CCoinsViewCache view(pcoinsTip);
        return GetTransactionSigOpCost(CTransaction(S), view, flags);
    }

    //! Relays S, which must be accepted, and returns the figure the mempool
    //! records for it.
    int64_t RelayAndReadRecorded()
    {
        {
            LOCK(cs_main);
            CValidationState st;
            const bool ok = AcceptToMemoryPool(mempool, st, MakeTransactionRef(S), false, nullptr, nullptr, true, 0);
            BOOST_REQUIRE_MESSAGE(ok, "the key-hash 2-of-2 spend must be accepted at relay; got: " << FormatStateMessage(st));
        }
        LOCK(mempool.cs);
        auto it = mempool.mapTx.find(S.GetHash());
        BOOST_REQUIRE(it != mempool.mapTx.end());
        return it->GetSigOpCost();
    }

    //! The figure the next template carries for S. The template must build,
    //! which runs CreateNewBlock's own validity check.
    int64_t TemplateFigure()
    {
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(Params()).CreateNewBlock(coinbaseSpk, true);
        BOOST_REQUIRE(tmpl);
        BOOST_REQUIRE_EQUAL(tmpl->block.vtx.size(), 2u);
        BOOST_CHECK(tmpl->block.vtx[1]->GetHash() == S.GetHash());
        return tmpl->vTxSigOpsCost[1];
    }
};

//! Moves the key-hash deployment's regtest activation height, on every
//! consensus tier, for the life of the object, and puts back the height it
//! found.
struct ScopedKeyhashActivationHeight {
    const int previous;
    explicit ScopedKeyhashActivationHeight(int nHeight)
        : previous(Params().GetConsensus(0).vDeployments[Consensus::DEPLOYMENT_DILITHIUM_KEYHASH].nActivationHeight)
    {
        UpdateRegtestActivationHeight(Consensus::DEPLOYMENT_DILITHIUM_KEYHASH, nHeight);
        SelectParams(CBaseChainParams::REGTEST);
    }
    ~ScopedKeyhashActivationHeight()
    {
        UpdateRegtestActivationHeight(Consensus::DEPLOYMENT_DILITHIUM_KEYHASH, previous);
        SelectParams(CBaseChainParams::REGTEST);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(mempool_consensus_sigop_parity_tests, SigopParitySetup)

BOOST_AUTO_TEST_CASE(the_mempool_records_the_sigop_cost_the_block_charges_for_a_v6_spend)
{
    int nNext;
    {
        LOCK(cs_main);
        nNext = chainActive.Height() + 1;
    }
    const int64_t blockCharge = BlockChargeAt(nNext);
    // Two key-hash checks at one sigop each; witness sigops are not scaled.
    BOOST_CHECK_EQUAL(blockCharge, 2);

    const int64_t recorded = RelayAndReadRecorded();
    BOOST_CHECK_MESSAGE(recorded == blockCharge,
        "the mempool records " << recorded << " sigops for a v6 spend the block charges " << blockCharge
        << " for; the miner sums the recorded figure against the block budget");

    // The miner carries the recorded figure, and the spend connects in a block
    // on the same tip.
    BOOST_CHECK_EQUAL(TemplateFigure(), blockCharge);
    BOOST_CHECK(BlockIsValid(std::vector<CMutableTransaction>(1, S)));
}

// The mempool prices for the block a transaction can next enter, not for the
// tip. With the key-hash check activating one block above the tip, the tip's
// flags charge the spend nothing and the next block charges both checks.
BOOST_AUTO_TEST_CASE(the_mempool_prices_for_the_next_block_not_the_tip)
{
    int nTip;
    {
        LOCK(cs_main);
        nTip = chainActive.Height();
    }
    ScopedKeyhashActivationHeight activation(nTip + 1);

    BOOST_REQUIRE_EQUAL(BlockChargeAt(nTip), 0);
    const int64_t blockCharge = BlockChargeAt(nTip + 1);
    BOOST_CHECK_EQUAL(blockCharge, 2);

    const int64_t recorded = RelayAndReadRecorded();
    BOOST_CHECK_MESSAGE(recorded == blockCharge,
        "with the key-hash check activating at the next block, the mempool records " << recorded
        << " sigops for a spend that block charges " << blockCharge << " for");
    BOOST_CHECK_EQUAL(TemplateFigure(), blockCharge);
    BOOST_CHECK(BlockIsValid(std::vector<CMutableTransaction>(1, S)));
}

BOOST_AUTO_TEST_SUITE_END()
