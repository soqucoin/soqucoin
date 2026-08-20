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
// ⛔ THAT INVARIANT DOES NOT HOLD TODAY, in the safe direction, for exactly one
// flag: SCRIPT_VERIFY_SCRIPT_RESTORE. See the last case in this file.

#include "policy/policy.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/standard.h"
#include "utilstrencodings.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(mempool_consensus_parity_tests, BasicTestingSetup)

namespace {

//! Evaluate a bare script under the given flags and report the error.
ScriptError Eval(const CScript& script, unsigned int flags)
{
    std::vector<std::vector<unsigned char> > stack;
    ScriptError serr = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;
    EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serr);
    return serr;
}

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
// ATMP's v6active lambda is DeploymentActiveAtHeight(tipHeight + 1, ...) and
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
BOOST_AUTO_TEST_CASE(script_restore_is_consensus_active_but_not_relay_standard)
{
    BOOST_CHECK_MESSAGE((STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_SCRIPT_RESTORE) == 0,
        "SCRIPT_VERIFY_SCRIPT_RESTORE is now in STANDARD_SCRIPT_VERIFY_FLAGS, so the policy "
        "and consensus split described here is closed. Update this test rather than deleting "
        "it, and check whether the SOQ-COV-012 omission list still lists it");

    // Prove the split changes behaviour, and prove WHICH WAY, rather than
    // reasoning about it. OP_MUL over two small numbers: valid arithmetic.
    CScript mul;
    mul << CScriptNum(6) << CScriptNum(7) << OP_MUL;

    const ScriptError withFlag = Eval(mul, SCRIPT_VERIFY_SCRIPT_RESTORE);
    const ScriptError asMempoolSeesIt = Eval(mul, STANDARD_SCRIPT_VERIFY_FLAGS);

    BOOST_TEST_MESSAGE("OP_MUL with SCRIPT_RESTORE:    " << EvalStack(mul, SCRIPT_VERIFY_SCRIPT_RESTORE));
    BOOST_TEST_MESSAGE("OP_MUL under STANDARD (mempool): " << EvalStack(mul, STANDARD_SCRIPT_VERIFY_FLAGS));
    BOOST_TEST_MESSAGE("OP_MUL with NO flags:            " << EvalStack(mul, 0));

    BOOST_CHECK_MESSAGE(withFlag == SCRIPT_ERR_OK,
        "OP_MUL must evaluate when SCRIPT_VERIFY_SCRIPT_RESTORE is set; that is the whole "
        "point of the flag, and ConnectBlock sets it for every block");

    // MEASURED: without the flag OP_MUL is a silent NO-OP, not an error.
    //   with SCRIPT_RESTORE     -> ok[2a]      (6 * 7 = 42, executed)
    //   under STANDARD (mempool) -> ok[06,07]  (untouched, operands still there)
    // Both "succeed". They leave DIFFERENT STACKS, so the same script has two
    // truth values. That is not the safe direction after all, and the next case
    // constructs the consequence.
    BOOST_CHECK_MESSAGE(asMempoolSeesIt == SCRIPT_ERR_OK,
        "OP_MUL now errors without SCRIPT_RESTORE rather than acting as a no-op. That would "
        "actually be an improvement: an error makes the divergence fail closed. Update this "
        "test and re-check the accept-then-reject case below");
    BOOST_CHECK_MESSAGE(withFlag == asMempoolSeesIt,
        "both paths still report success; the divergence is in the STACK, not the error code");
}

// ---------------------------------------------------------------------------
// ⛔⛔ THE CONSEQUENCE, CONSTRUCTED. Because the restored opcodes are NO-OPS
// rather than errors when the flag is clear, a single script has two different
// truth values: one under the mempool's flag set and another under the flag set
// ConnectBlock uses. Both directions are reachable, and one of them is the
// template-stalling shape that live bug daf9fd85 produced.
//
// This is what makes the omission unsafe rather than merely restrictive. Had the
// opcodes been DISABLED without the flag, policy would simply be stricter and
// the worst case would be an unusable feature. As no-ops they silently change
// the meaning of a script instead.
//
// Reachability: EvalScript runs user-supplied opcodes only from a v6
// P2WSH-Dilithium witnessScript. v6 is NOT_SCHEDULED on mainnet, so this is not
// live there, but it is ALWAYS_ACTIVE and relay-standard on stagenet, testnet
// and regtest, which means the accept-then-reject path is live on the rehearsal
// network today, and becomes live on mainnet the moment P2WSH-Dilithium
// activates.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(a_single_script_has_two_truth_values_across_the_split)
{
    // Note OP_EQUAL is itself gated, on SCRIPT_VERIFY_V6_CONTROLFLOW, and that
    // flag IS paired across both paths, so it cannot be used to express the
    // comparison here. The divergence has to be read off the stack directly,
    // which is also the more honest way to show it.

    // 0 * 7 = 0. Consensus multiplies and leaves an EMPTY stack element, which
    // is FALSE. The mempool skips the multiply and leaves the operands, whose
    // top element is 0x07, which is TRUE.
    CScript falseUnderConsensusTrueUnderRelay;
    falseUnderConsensusTrueUnderRelay << CScriptNum(0) << CScriptNum(7) << OP_MUL;

    const std::string consensusView = EvalStack(falseUnderConsensusTrueUnderRelay,
                                                STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_SCRIPT_RESTORE);
    const std::string mempoolView   = EvalStack(falseUnderConsensusTrueUnderRelay,
                                                STANDARD_SCRIPT_VERIFY_FLAGS);

    BOOST_TEST_MESSAGE("0 7 OP_MUL under consensus flags: " << consensusView);
    BOOST_TEST_MESSAGE("0 7 OP_MUL under mempool flags:   " << mempoolView);

    BOOST_CHECK_MESSAGE(consensusView != mempoolView,
        "the same script now evaluates identically on both paths, so the SCRIPT_RESTORE "
        "divergence is closed. Good; update this test rather than deleting it");

    // Consensus: one empty element, the canonical FALSE.
    BOOST_CHECK_MESSAGE(consensusView == "ok[]",
        "expected consensus to compute 0 * 7 = 0 and leave FALSE, got " + consensusView);
    // Mempool: operands untouched, top element 0x07, which is TRUE.
    BOOST_CHECK_MESSAGE(mempoolView == "ok[,07]",
        "expected the mempool to skip the multiply and leave the operands, got " + mempoolView +
        ". If the shape has changed, re-derive the demonstration; the property under test is "
        "that the two flag sets disagree about what this script computed");
}

// The same divergence stated as the invariant it breaks, so the reason it
// matters does not depend on one hand-built script surviving future edits.
BOOST_AUTO_TEST_CASE(restored_opcodes_are_noops_not_errors_which_is_the_unsafe_shape)
{
    // Every opcode SCRIPT_VERIFY_SCRIPT_RESTORE re-enables. For each one, the
    // stack it leaves must be the same under both flag sets, or that opcode can
    // carry a transaction that relays and cannot be mined.
    struct Case { const char* name; CScript script; };
    std::vector<Case> cases;
    {
        CScript s; s << CScriptNum(6) << CScriptNum(7) << OP_MUL;   cases.push_back({"OP_MUL", s});
    }
    {
        CScript s; s << CScriptNum(84) << CScriptNum(2) << OP_DIV;  cases.push_back({"OP_DIV", s});
    }
    {
        CScript s; s << CScriptNum(85) << CScriptNum(4) << OP_MOD;  cases.push_back({"OP_MOD", s});
    }

    for (const Case& c : cases) {
        const std::string consensusView = EvalStack(c.script,
                                                    STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_SCRIPT_RESTORE);
        const std::string mempoolView = EvalStack(c.script, STANDARD_SCRIPT_VERIFY_FLAGS);
        BOOST_TEST_MESSAGE(std::string(c.name) + ": consensus " + consensusView +
                           "  mempool " + mempoolView);
        BOOST_CHECK_MESSAGE(consensusView != mempoolView,
            std::string(c.name) + " now agrees across both flag sets. If the omission is "
            "being closed opcode by opcode that is worse than either end state, because the "
            "set of scripts that mean two different things becomes harder to describe. Work "
            "out which ones changed and finish the job");
    }

    // OP_CAT is the CONTROL, and it is the interesting one. It belongs to the
    // same Satoshi-restoration family and is described in validation.cpp as
    // "genesis-active like OP_CAT" — but unlike MUL/DIV/MOD it is NOT gated on
    // SCRIPT_VERIFY_SCRIPT_RESTORE at all, so both paths agree about it.
    //
    // That is what correct looks like, and it shows the divergence is an
    // accident of which opcodes ended up behind the flag rather than a
    // considered policy about arithmetic. Whoever decides the fix should note
    // that half of this feature is already unconditional.
    CScript cat;
    cat << std::vector<unsigned char>{0xaa} << std::vector<unsigned char>{0xbb} << OP_CAT;
    BOOST_CHECK_MESSAGE(
        EvalStack(cat, STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_SCRIPT_RESTORE) ==
        EvalStack(cat, STANDARD_SCRIPT_VERIFY_FLAGS),
        "OP_CAT has started depending on SCRIPT_VERIFY_SCRIPT_RESTORE. It was ungated and "
        "therefore consistent across relay and consensus; gating it extends the divergence");
}

BOOST_AUTO_TEST_SUITE_END()
