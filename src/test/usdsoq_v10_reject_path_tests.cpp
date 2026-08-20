// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// usdsoq_v10_reject_path_tests.cpp — reject-path coverage for witness v10
// (confidential USDSOQ, SoquObscura Tier A), written against the Gate 0
// acceptance criterion in bead r0vn:
//
//   A reject rule is NOT DONE until a test drives a FAILING INPUT through
//   ConnectBlock and observes THAT EXACT REJECT STRING.
//
// Every rule exercised here was previously unreachable while the full suite ran
// 597/597 green, which is the whole reason the criterion exists:
//
//   * bad-txns-usdsoq-authority-must-be-transparent (SOQ-ARCH-004, GENIUS Act
//     §4(a)(2)) — the loop was gated on IsUSDSOQ() (v7) while every branch inside
//     it tested IsConfidential(), and one scriptPubKey byte cannot be two
//     opcodes. Empty set, so the rule could not fire (bead don9).
//   * bad-txns-usdsoq-conf-input — the identical defect in the authority BURN
//     input loop, left behind when the output loop was widened (bead n1vf).
//   * bad-txns-usdsoq-confidential-not-active — reachable in principle but
//     SHADOWED by SOQ-ARCH-001, which runs earlier in the same ConnectBlock on
//     the same flags. Pinned below so the shadowing cannot change silently.
//
// Two things had to exist before any of this could be tested at all, and their
// absence is why it never was:
//
//  1. A way to ACTIVATE a height-gated deployment on regtest.
//     UpdateRegtestBIP9Parameters only writes nStartTime/nTimeout, which
//     DeploymentActiveAtHeight never reads. SoquObscura ships NOT_SCHEDULED on
//     all four networks, so every SCRIPT_VERIFY_SOQUOBSCURA-gated path was
//     unreachable from any test. See UpdateRegtestActivationHeight.
//  2. Reject-string observation. ProcessNewBlock returns a bool, so the existing
//     harness can only assert "the tip did not move" — which passes for the
//     WRONG reject just as happily as the right one. These tests solve the block
//     first and run TestBlockValidity, which yields the CValidationState.
//
// Fixture shape (Dilithium v1 coinbase, 240 blocks, direct coins-view seeding)
// follows usdsoq_v7_conservation_harness_tests.cpp.

#include "chainparams.h"
#include "consensus/params.h"
#include "consensus/usdsoq.h"
#include "consensus/validation.h"
#include "key.h"
#include "miner.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/standard.h"
#include "coins.h"
#include "txdb.h"
#include "uint256.h"
#include "validation.h"
#include "crypto/sha256.h"
#include "test/test_bitcoin.h"
#include "test/testutil.h"   // ScopedRegtestActivation

#include <boost/test/unit_test.hpp>
#include <algorithm>

namespace {

static const int COINBASE_MATURITY_SOQ = 60 * 4;  // 240, regtest

// OP_N <32-byte program> — the one shape every Soqucoin witness version uses.
static CScript MakeVnSpk(opcodetype version, const std::vector<unsigned char>& rawPubkey)
{
    uint256 pkHash;
    CSHA256().Write(rawPubkey.data(), rawPubkey.size()).Finalize(pkHash.begin());
    CScript spk;
    spk << version << std::vector<unsigned char>(pkHash.begin(), pkHash.end());
    return spk;
}

static std::vector<unsigned char> Prefixed(const std::vector<unsigned char>& rawPubkey)
{
    std::vector<unsigned char> out;
    out.reserve(rawPubkey.size() + 1);
    out.push_back(0x00);
    out.insert(out.end(), rawPubkey.begin(), rawPubkey.end());
    return out;
}

} // namespace

struct V10RejectPathSetup : public TestingSetup {
    CKey coinbaseKey;
    CScript coinbaseSpk;
    std::vector<unsigned char> coinbasePkBytes;
    std::vector<CTransaction> coinbaseTxns;

    V10RejectPathSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        coinbaseKey.MakeNewKey(true);
        CPubKey pk = coinbaseKey.GetPubKey();   // local first — never .GetPubKey().begin() inline
        BOOST_REQUIRE(pk.IsValid());
        coinbasePkBytes.assign(pk.begin(), pk.end());
        BOOST_REQUIRE_EQUAL(coinbasePkBytes.size(), 1312u);
        coinbaseSpk = V1Spk();
        BOOST_REQUIRE_EQUAL(coinbaseSpk.size(), 34u);

        for (int i = 0; i < COINBASE_MATURITY_SOQ; i++) {
            CBlock b = CreateAndProcessBlock({}, coinbaseSpk);
            BOOST_REQUIRE_MESSAGE(b.vtx.size() > 0, "block must have coinbase");
            coinbaseTxns.push_back(*b.vtx[0]);
        }
    }

    CScript V1Spk()  const { return MakeVnSpk(OP_1,  coinbasePkBytes); }  // native SOQ
    CScript V5Spk()  const { return MakeVnSpk(OP_5,  coinbasePkBytes); }  // USDSOQ authority marker
    CScript V7Spk()  const { return MakeVnSpk(OP_7,  coinbasePkBytes); }  // USDSOQ transparent
    CScript V10Spk() const { return MakeVnSpk(OP_10, coinbasePkBytes); }  // USDSOQ confidential (Tier A)

    // Solve a block and CONNECT it (used to build the coinbase chain).
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& spk)
    {
        CBlock block = BuildSolvedBlock(txns, spk);
        std::shared_ptr<const CBlock> shared = std::make_shared<const CBlock>(block);
        bool fNewBlock = false;
        ProcessNewBlock(Params(), shared, true, &fNewBlock);
        return block;
    }

    // Solve a block on top of the tip WITHOUT connecting it, so the caller can run
    // TestBlockValidity and read the reject reason out of CValidationState.
    CBlock BuildSolvedBlock(const std::vector<CMutableTransaction>& txns, const CScript& spk)
    {
        const CChainParams& cp = Params();
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(cp).CreateNewBlock(spk, true);
        BOOST_REQUIRE_MESSAGE(tmpl != nullptr, "CreateNewBlock must not return nullptr");
        CBlock& block = tmpl->block;
        block.vtx.resize(1);
        {
            // Drop the witness commitment CreateNewBlock generated for the EMPTY
            // template, then regenerate it over our actual vtx set.
            CMutableTransaction coinbaseMut(*block.vtx[0]);
            coinbaseMut.vout.erase(
                std::remove_if(coinbaseMut.vout.begin(), coinbaseMut.vout.end(),
                    [](const CTxOut& o) {
                        return o.scriptPubKey.size() >= 38 &&
                               o.scriptPubKey[0] == OP_RETURN && o.scriptPubKey[1] == 0x24 &&
                               o.scriptPubKey[2] == 0xaa && o.scriptPubKey[3] == 0x21 &&
                               o.scriptPubKey[4] == 0xa9 && o.scriptPubKey[5] == 0xed;
                    }),
                coinbaseMut.vout.end());
            coinbaseMut.vin[0].scriptWitness.stack.clear();
            block.vtx[0] = MakeTransactionRef(std::move(coinbaseMut));
        }
        for (const CMutableTransaction& tx : txns)
            block.vtx.push_back(MakeTransactionRef(tx));
        GenerateCoinbaseCommitment(block, chainActive.Tip(), cp.GetConsensus(0));
        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
        while (!CheckProofOfWork(block.GetPoWHash(), block.nBits, cp.GetConsensus(0)))
            ++block.nNonce;
        return block;
    }

    // Run a solved block through the full ConnectBlock path (fJustCheck) and return
    // the reject reason, or "" if it validated. THE assertion primitive for r0vn:
    // "tip did not move" cannot tell a correct reject from an accidental one.
    std::string RejectReasonFor(const std::vector<CMutableTransaction>& txns)
    {
        CBlock B = BuildSolvedBlock(txns, coinbaseSpk);
        CValidationState st;
        bool ok;
        {
            LOCK(cs_main);
            ok = TestBlockValidity(st, Params(), B, chainActive.Tip(), true, true);
        }
        if (ok) return std::string();
        BOOST_TEST_MESSAGE("reject: " << st.GetRejectReason()
            << (st.GetDebugMessage().empty() ? "" : " | " + st.GetDebugMessage()));
        return st.GetRejectReason();
    }

    // Seed a mature, spendable coin of an arbitrary witness version straight into
    // the UTXO set. Direct pcoinsTip modification (no intermediate CCoinsViewCache:
    // an intermediate Flush() would overwrite pcoinsTip's hashBlock and trip
    // ConnectBlock's assertion).
    COutPoint SeedCoin(const CScript& spk, CAmount value, uint8_t tag)
    {
        uint256 txid;
        txid.begin()[0] = tag;   // distinct txid per seeded coin
        {
            LOCK(cs_main);
            CCoinsModifier c = pcoinsTip->ModifyCoins(txid);
            c->Clear();
            c->fCoinBase = false;
            c->nHeight   = 1;    // mature, non-coinbase
            c->nVersion  = 2;
            c->vout.resize(1);
            c->vout[0].nValue       = value;
            c->vout[0].scriptPubKey = spk;
        }
        return COutPoint(txid, 0);
    }

    void SignInput(CMutableTransaction& tx, unsigned int idx, const CScript& scriptCode, CAmount amount)
    {
        CTransaction ctxForSign(tx);
        uint256 sighash = SignatureHash(scriptCode, ctxForSign, idx, SIGHASH_ALL,
                                        amount, SIGVERSION_WITNESS_V0, nullptr);
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(coinbaseKey.Sign(sighash, sig));
        sig.push_back((unsigned char)SIGHASH_ALL);
        tx.vin[idx].scriptWitness.stack.clear();
        tx.vin[idx].scriptWitness.stack.push_back(sig);
        tx.vin[idx].scriptWitness.stack.push_back(Prefixed(coinbasePkBytes));
    }

    // An AUTHORITY tx (carries the OP_5 marker, so it is exempt from per-asset
    // conservation and takes the SOQ-ARCH-004 authority branch). `assetIn` is an
    // optional USDSOQ input to burn; `extraOut` an optional extra output.
    // g_usdsoq_authority is never initialized in this fixture, so M-of-N signature
    // verification is skipped and the marker alone confers authority status.
    CMutableTransaction BuildAuthorityTx(const CTransaction& feeCoinbase,
                                         const COutPoint* assetIn, CAmount assetInVal,
                                         const CScript& assetInSpk,
                                         const CTxOut* extraOut)
    {
        const CAmount feeVal = feeCoinbase.vout[0].nValue;
        CMutableTransaction tx; tx.nVersion = 2;

        unsigned int feeIdx = 0;
        if (assetIn) {
            CTxIn a; a.prevout = *assetIn; a.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(a);
            feeIdx = 1;
        }
        CTxIn f; f.prevout = COutPoint(feeCoinbase.GetHash(), 0);
        f.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(f);

        CTxOut mark; mark.nValue = 10000; mark.scriptPubKey = V5Spk(); tx.vout.push_back(mark);
        if (extraOut) tx.vout.push_back(*extraOut);
        CTxOut chg; chg.nValue = feeVal - 20000 - (extraOut ? extraOut->nValue : 0);
        chg.scriptPubKey = V1Spk(); tx.vout.push_back(chg);

        if (assetIn) SignInput(tx, 0, assetInSpk, assetInVal);
        SignInput(tx, feeIdx, coinbaseSpk, feeVal);
        return tx;
    }
};

BOOST_FIXTURE_TEST_SUITE(usdsoq_v10_reject_path_tests, V10RejectPathSetup)

// ---------------------------------------------------------------------------
// GUARD ON THE TEST LEVER ITSELF. Everything below depends on being able to turn
// SoquObscura on, and the obvious lever (UpdateRegtestBIP9Parameters) silently
// does nothing for a height-gated deployment. If this ever regresses, the other
// tests would go green by never reaching the rule they claim to exercise —
// exactly the failure mode this file exists to close.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(regtest_activation_lever_actually_activates)
{
    const int h = chainActive.Height() + 1;
    BOOST_REQUIRE_MESSAGE(
        !Consensus::DeploymentActiveAtHeight(h, Params().GetConsensus(h),
                                             Consensus::DEPLOYMENT_SOQUOBSCURA),
        "SoquObscura must ship DORMANT on regtest (bead 2pru)");

    // The BIP9 lever must be a no-op here — nStartTime/nTimeout are not consulted
    // once nActivationHeight is set.
    UpdateRegtestBIP9Parameters(Consensus::DEPLOYMENT_SOQUOBSCURA, 0, Consensus::BIP9Deployment::NO_TIMEOUT);
    BOOST_CHECK_MESSAGE(
        !Consensus::DeploymentActiveAtHeight(h, Params().GetConsensus(h),
                                             Consensus::DEPLOYMENT_SOQUOBSCURA),
        "UpdateRegtestBIP9Parameters must NOT activate a height-gated deployment "
        "(if this fails, the F8 no-op footgun has been fixed and this test should "
        "be updated rather than deleted)");
    UpdateRegtestBIP9Parameters(Consensus::DEPLOYMENT_SOQUOBSCURA, 0, 0);

    {
        ScopedRegtestActivation on(Consensus::DEPLOYMENT_SOQUOBSCURA, 0);
        BOOST_CHECK_MESSAGE(
            Consensus::DeploymentActiveAtHeight(h, Params().GetConsensus(h),
                                                Consensus::DEPLOYMENT_SOQUOBSCURA),
            "the activation-height lever must reach the consensus struct that covers "
            "height " + std::to_string(h) + " (regtest indexes three of them)");
    }
    BOOST_CHECK_MESSAGE(
        !Consensus::DeploymentActiveAtHeight(h, Params().GetConsensus(h),
                                             Consensus::DEPLOYMENT_SOQUOBSCURA),
        "the guard must restore dormancy on scope exit");
}

// ---------------------------------------------------------------------------
// don9 REMAINDER — SOQ-ARCH-004 / GENIUS Act §4(a)(2).
// An authority transaction (mint/burn/freeze/rotate) that emits a CONFIDENTIAL
// USDSOQ output must be rejected: supply auditability requires the mint/burn
// boundary to be visible. Before witness v10 existed this rule could not fire at
// all, and it was "true" only because the state was unconstructable.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(connectblock_rejects_confidential_usdsoq_authority_output)
{
    ScopedRegtestActivation on(Consensus::DEPLOYMENT_SOQUOBSCURA, 0);

    CTxOut v10Out; v10Out.nValue = 1 * COIN; v10Out.scriptPubKey = V10Spk();
    CMutableTransaction bad = BuildAuthorityTx(coinbaseTxns[0], nullptr, 0, CScript(), &v10Out);

    BOOST_CHECK_EQUAL(RejectReasonFor({bad}), "bad-txns-usdsoq-authority-must-be-transparent");
}

// Reachability control for the case above: the SAME authority tx shape with a
// TRANSPARENT v7 output must connect. Without this, a rejection for any unrelated
// reason would read as the rule working.
BOOST_AUTO_TEST_CASE(authority_tx_with_transparent_usdsoq_output_is_accepted)
{
    ScopedRegtestActivation on(Consensus::DEPLOYMENT_SOQUOBSCURA, 0);

    CTxOut v7Out; v7Out.nValue = 1 * COIN; v7Out.scriptPubKey = V7Spk();
    CMutableTransaction good = BuildAuthorityTx(coinbaseTxns[1], nullptr, 0, CScript(), &v7Out);

    BOOST_CHECK_MESSAGE(RejectReasonFor({good}).empty(),
        "an authority MINT to a transparent v7 output must connect — otherwise the "
        "confidential-output rejection above proves nothing");
}

// ---------------------------------------------------------------------------
// n1vf — bad-txns-usdsoq-conf-input.
// An authority transaction that SPENDS a confidential USDSOQ input must be
// rejected. nUSDSOQBurned is a plaintext sum read from the block undo, so a
// hidden burn amount would desynchronise the supply counter from the chain.
// This is the reject whose own error text says the state "should not exist";
// what did not exist was the rule, because the enclosing guard was v7-only.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(connectblock_rejects_confidential_usdsoq_input_in_authority_tx)
{
    ScopedRegtestActivation on(Consensus::DEPLOYMENT_SOQUOBSCURA, 0);

    const CAmount v10Val = 5 * COIN;
    COutPoint v10op = SeedCoin(V10Spk(), v10Val, 0xa0);
    CMutableTransaction burn = BuildAuthorityTx(coinbaseTxns[2], &v10op, v10Val, V10Spk(), nullptr);

    BOOST_CHECK_EQUAL(RejectReasonFor({burn}), "bad-txns-usdsoq-conf-input");
}

// Reachability control: the identical authority burn of a TRANSPARENT v7 input
// must connect, isolating the confidentiality of the input as the cause.
BOOST_AUTO_TEST_CASE(authority_burn_of_transparent_usdsoq_input_is_accepted)
{
    ScopedRegtestActivation on(Consensus::DEPLOYMENT_SOQUOBSCURA, 0);

    // A burn must be backed by real supply, so MINT first and CONNECT that block:
    // TestBlockValidity runs with fJustCheck, which deliberately does not commit the
    // supply delta (BUG-18), so a dry-run mint would leave the counter at zero and
    // the burn would fail with bad-usdsoq-supply-underflow instead of the reason
    // under test. Seeding the coin directly has the same problem — a seeded v7 coin
    // is USDSOQ the supply counter never saw.
    const CAmount v7Val = 5 * COIN;
    CTxOut v7Out; v7Out.nValue = v7Val; v7Out.scriptPubKey = V7Spk();
    CMutableTransaction mint = BuildAuthorityTx(coinbaseTxns[3], nullptr, 0, CScript(), &v7Out);
    CBlock mintBlock = CreateAndProcessBlock({mint}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == mintBlock.GetHash(),
        "the authority mint block must connect before anything can be burned");

    // BuildAuthorityTx lays out [0] = OP_5 marker, [1] = extra output, [2] = change.
    COutPoint v7op(mint.GetHash(), 1);
    CMutableTransaction burn = BuildAuthorityTx(coinbaseTxns[4], &v7op, v7Val, V7Spk(), nullptr);

    BOOST_CHECK_MESSAGE(RejectReasonFor({burn}).empty(),
        "an authority burn of a transparent v7 input must connect");
}

// ---------------------------------------------------------------------------
// n1vf — THE SHADOWED RULE, PINNED.
// bad-txns-usdsoq-confidential-not-active is unreachable: SOQ-ARCH-001 runs
// earlier in the same ConnectBlock, on the same flags, and rejects EVERY
// confidential output with bad-txns-confidential-not-active. This test does not
// pretend the asset-specific rule fires; it records WHICH rule does, so the
// shadowing relationship cannot change without a test changing with it.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(preactivation_v10_output_is_rejected_by_soq_arch_001_not_the_usdsoq_rule)
{
    // Deliberately NO ScopedRegtestActivation — this is the shipped dormant state.
    const int h = chainActive.Height() + 1;
    BOOST_REQUIRE(!Consensus::DeploymentActiveAtHeight(h, Params().GetConsensus(h),
                                                       Consensus::DEPLOYMENT_SOQUOBSCURA));

    // The v10 output is funded by a v7 USDSOQ input of the SAME value, so per-asset
    // conservation is satisfied. That matters: conservation lives in
    // Consensus::CheckTxInputs, which runs in ConnectBlock's FIRST pass, strictly
    // before SOQ-ARCH-001. Funding a v10 output from plain SOQ would trip
    // bad-txns-usdsoq-not-conserved first and this test would pin the wrong rule.
    const CAmount val = 5 * COIN;
    COutPoint v7op = SeedCoin(V7Spk(), val, 0xb7);

    CMutableTransaction tx; tx.nVersion = 2;
    CTxIn in; in.prevout = v7op; in.nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin.push_back(in);
    CTxOut o; o.nValue = val; o.scriptPubKey = V10Spk(); tx.vout.push_back(o);
    SignInput(tx, 0, V7Spk(), val);

    const std::string why = RejectReasonFor({tx});
    BOOST_CHECK_EQUAL(why, "bad-txns-confidential-not-active");
    BOOST_CHECK_MESSAGE(why != "bad-txns-usdsoq-confidential-not-active",
        "if the asset-specific rule starts firing, SOQ-ARCH-001 has been narrowed and "
        "the Tier A pre-activation posture must be re-derived, not assumed");
}

// ---------------------------------------------------------------------------
// PER-ASSET CONSERVATION MUST SEE BOTH USDSOQ MODES.
// The mirror of usdsoq_v7_conservation_harness_tests::v7_minted_from_soq_is_rejected,
// for v10. With the conservation predicate v7-only, a v10 output was invisible to
// this rule AND to the IsNativeSOQ() fee filters, so a tx emitting one from plain
// SOQ inputs both minted confidential USDSOQ from nothing and pushed the same value
// into nFees for the miner to claim. Unreachable pre-activation, which is why it
// could sit here; catastrophic the moment SoquObscura activates.
//
// Note the rule is deliberately NOT deployment-gated, so it fires in the dormant
// state too — that is what makes the v10 shape reserved from genesis rather than
// something a later soft fork has to add.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(v10_minted_from_soq_is_rejected)
{
    CMutableTransaction tx; tx.nVersion = 2;
    const CTransaction& cb = coinbaseTxns[6];
    const CAmount inVal = cb.vout[0].nValue;
    CTxIn in; in.prevout = COutPoint(cb.GetHash(), 0); in.nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin.push_back(in);
    CTxOut o; o.nValue = inVal - 10000; o.scriptPubKey = V10Spk(); tx.vout.push_back(o);
    SignInput(tx, 0, coinbaseSpk, inVal);

    BOOST_CHECK_EQUAL(RejectReasonFor({tx}), "bad-txns-usdsoq-not-conserved");
}

// Same shape with SoquObscura ACTIVE: conservation is structural, not gated, so
// activation must not open the mint path. This is the assertion that would have
// caught the defect at activation time rather than after it.
BOOST_AUTO_TEST_CASE(v10_minted_from_soq_is_rejected_after_activation_too)
{
    ScopedRegtestActivation on(Consensus::DEPLOYMENT_SOQUOBSCURA, 0);

    CMutableTransaction tx; tx.nVersion = 2;
    const CTransaction& cb = coinbaseTxns[7];
    const CAmount inVal = cb.vout[0].nValue;
    CTxIn in; in.prevout = COutPoint(cb.GetHash(), 0); in.nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin.push_back(in);
    CTxOut o; o.nValue = inVal - 10000; o.scriptPubKey = V10Spk(); tx.vout.push_back(o);
    SignInput(tx, 0, coinbaseSpk, inVal);

    BOOST_CHECK_EQUAL(RejectReasonFor({tx}), "bad-txns-usdsoq-not-conserved");
}

// Reachability control: a CONSERVING v10 transfer must still be accepted once the
// privacy layer is active, so the rule above rejects minting rather than rejecting
// v10 outright. Also pins that the widened input-isolation predicate lets a v10
// input pay for its own transfer.
BOOST_AUTO_TEST_CASE(conserving_v10_transfer_is_accepted_after_activation)
{
    ScopedRegtestActivation on(Consensus::DEPLOYMENT_SOQUOBSCURA, 0);

    const CAmount val = 5 * COIN;
    COutPoint v10op = SeedCoin(V10Spk(), val, 0xb1);
    const CTransaction& cb = coinbaseTxns[8];
    const CAmount feeVal = cb.vout[0].nValue;

    CMutableTransaction tx; tx.nVersion = 2;
    { CTxIn i0; i0.prevout = v10op; i0.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(i0); }
    { CTxIn i1; i1.prevout = COutPoint(cb.GetHash(), 0); i1.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(i1); }
    { CTxOut o; o.nValue = val;             o.scriptPubKey = V10Spk();  tx.vout.push_back(o); }
    { CTxOut o; o.nValue = feeVal - 10000;  o.scriptPubKey = V1Spk();   tx.vout.push_back(o); }
    SignInput(tx, 0, V10Spk(), val);
    SignInput(tx, 1, coinbaseSpk, feeVal);

    BOOST_CHECK_MESSAGE(RejectReasonFor({tx}).empty(),
        "a conserving v10 -> v10 transfer with a SOQ fee input must connect once "
        "SoquObscura is active");
}

// ---------------------------------------------------------------------------
// DORMANCY, OUTPUT SIDE (r0vn definition-of-done #4, F3 class).
// A witness version that consensus does not yet enforce must never be relayable:
// such an output confirms and is then anyone-can-spend, which is fund loss, not
// a soft failure. That was the live mainnet defect fixed for v5-v9 in
// soqucoin#37. v10 carries the same exposure and must stay non-standard even
// with every currently-allocated version switched on.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(v10_output_is_never_relay_standard)
{
    WitnessVersionMask everyAllocated = 0;
    for (int v = 2; v <= 9; ++v) everyAllocated |= WitnessVersionBit(v);

    txnouttype whichType = TX_NONSTANDARD;
    BOOST_CHECK_MESSAGE(!::IsStandard(V10Spk(), whichType, true, everyAllocated),
        "a v10 output must be non-standard even when v2-v9 are all active — v10 has "
        "no deployment, so it is anyone-can-spend at the script layer");
    // Two independent reasons hold it shut, and the test asserts both survive:
    // the activeWitnessVersions gate in policy.cpp, and Solver having no
    // classification for OP_10 <32> at all (TX_NONSTANDARD). Forcing the mask bit
    // on isolates the second one.
    BOOST_CHECK_MESSAGE(!::IsStandard(V10Spk(), whichType, true, everyAllocated | WitnessVersionBit(10)),
        "v10 must still be non-standard with its mask bit forced on: Solver has no "
        "TX_WITNESS_V10 form, so granting a deployment alone would NOT make it "
        "relayable — the allocation has to be completed in Solver too");
    // Solver leaves typeRet untouched when it returns false, so assert on Solver's
    // return value rather than on whichType (which is only meaningful on true).
    std::vector<std::vector<unsigned char> > vSolutions;
    BOOST_CHECK_MESSAGE(!Solver(V10Spk(), whichType, vSolutions),
        "Solver must have no template for OP_10 <32>");
}

BOOST_AUTO_TEST_SUITE_END()
