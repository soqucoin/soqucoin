// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// usdsoq_commit_discipline_tests.cpp — SOQ-I013. USDSOQ side effects must not
// be persisted before the block is known to be valid.
//
// THE DEFECT
// ──────────
// ConnectBlock queues per-input script checks during its FIRST pass and only
// collects the verdict at `control.Wait()`, near the very end. The USDSOQ
// enforcement block runs in between, and it writes straight through:
//
//     authority outpoint   -> global + LevelDB   (before the barrier)
//     frozen outpoint set  -> LevelDB            (before the barrier)
//     supply counters      -> global + LevelDB   (before the barrier)
//     control.Wait()       <- the script verdict arrives HERE
//     BTCSOQ minted/supply -> LevelDB            (after the barrier)
//
// So a block that is valid right up until a script check fails still mutates
// USDSOQ state permanently. The UTXO cache is discarded on failure; these
// writes are not. The node's USDSOQ state then describes a block that is not on
// any chain — the same divergence class as SOQ-I012, arrived at from the other
// direction.
//
// The `!fJustCheck` guards on these writes do not help. They protect dry runs
// (getblocktemplate); this is a REAL connect that fails late.
//
// BTCSOQ does not have this bug. Its block carries an explicit "COMMIT
// DISCIPLINE (review finding, 2C)" note, collects side effects into
// btcsoqPending* containers, and commits them in one place after every gate has
// passed. The review that produced that discipline did not come back and apply
// it to USDSOQ — the fourth instance in this codebase of a fix landing on one
// of two sibling subsystems.
//
// REACHABILITY
// ────────────
// LIVE TODAY on stagenet, testnet and regtest, where DEPLOYMENT_USDSOQ is
// active from height 0. Dormant on mainnet until activation (v5 outputs cannot
// be created before it — SOQ-I009).
//
// Credit: identified by cold review of main, independently of this sweep.

#include "chainparams.h"
#include "consensus/usdsoq.h"
#include "consensus/validation.h"
#include "test/dilithium_chain_setup.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

struct UsdsoqCommitSetup : public DilithiumChainSetup {
    UsdsoqTestAuthority auth;

    //! A valid BOOTSTRAP authority tx. Advances the tracked authority outpoint.
    CMutableTransaction BuildBootstrapAuthorityTx(const CTransaction& feeCoinbase)
    {
        const CAmount feeVal = feeCoinbase.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;
        CTxIn in;
        in.prevout = COutPoint(feeCoinbase.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);
        CTxOut mark; mark.nValue = 10000; mark.scriptPubKey = auth.MarkerSpk();
        tx.vout.push_back(mark);
        CTxOut chg; chg.nValue = feeVal - 20000; chg.scriptPubKey = Spk(OP_1);
        tx.vout.push_back(chg);
        SignInput(tx, 0, coinbaseSpk, feeVal);
        auth.Sign(tx, 0, auth.MarkerSpk());
        return tx;
    }

    //! An ordinary spend whose signature is garbage. Structurally fine — the
    //! last witness item is a real 0x00-prefixed Dilithium pubkey so it clears
    //! CheckTransaction — but it fails Dilithium verification, and that verdict
    //! only arrives at control.Wait().
    CMutableTransaction BuildBadSignatureSpend(const CTransaction& cb)
    {
        const CAmount inVal = cb.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;
        CTxIn in;
        in.prevout = COutPoint(cb.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);
        CTxOut out; out.nValue = inVal - 10000; out.scriptPubKey = Spk(OP_1);
        tx.vout.push_back(out);
        tx.vin[0].scriptWitness.stack.clear();
        tx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(2421, 0xAB));
        tx.vin[0].scriptWitness.stack.push_back(PrefixedPubkey(coinbasePkBytes));
        return tx;
    }
};

BOOST_FIXTURE_TEST_SUITE(usdsoq_commit_discipline_tests, UsdsoqCommitSetup)

// Reachability control. The authority tx on its own must connect and advance
// the tracker, otherwise the negative case below proves nothing.
BOOST_AUTO_TEST_CASE(authority_tx_alone_advances_the_tracker)
{
    CMutableTransaction boot = BuildBootstrapAuthorityTx(coinbaseTxns[0]);
    CBlock b = CreateAndProcessBlock({boot}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b.GetHash());

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(!g_usdsoq_authority_outpoint.IsNull(),
        "control: a valid authority block must advance the tracker");
}

// THE DEFECT. Same authority tx, in a block that also carries a
// bad-signature spend. The block must be rejected AND leave no trace.
BOOST_AUTO_TEST_CASE(a_rejected_block_must_not_advance_the_authority_tracker)
{
    {
        LOCK(cs_main);
        BOOST_REQUIRE(g_usdsoq_authority_outpoint.IsNull());
    }

    CMutableTransaction boot = BuildBootstrapAuthorityTx(coinbaseTxns[0]);
    CMutableTransaction bad  = BuildBadSignatureSpend(coinbaseTxns[1]);

    CBlock b = CreateAndProcessBlock({boot, bad}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() != b.GetHash(),
        "the block carries an invalid signature and must be rejected");

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(g_usdsoq_authority_outpoint.IsNull(),
        "SOQ-I013: a REJECTED block advanced the USDSOQ authority outpoint. The "
        "tracker now points into a block that is on no chain, so the next "
        "legitimate authority tx is rejected with bad-usdsoq-authority-outpoint "
        "and the node wedges. USDSOQ commits before control.Wait(); BTCSOQ "
        "commits after it. Move the USDSOQ commits past the barrier");
}

// Same property for the supply counters, which are the auditable money number.
BOOST_AUTO_TEST_CASE(a_rejected_block_must_not_move_the_supply_counters)
{
    CAmount mintedBefore = 0, burnedBefore = 0;
    {
        LOCK(cs_main);
        mintedBefore = g_usdsoq_supply.TotalMinted();
        burnedBefore = g_usdsoq_supply.TotalBurned();
    }

    CMutableTransaction boot = BuildBootstrapAuthorityTx(coinbaseTxns[0]);
    CMutableTransaction bad  = BuildBadSignatureSpend(coinbaseTxns[1]);
    CBlock b = CreateAndProcessBlock({boot, bad}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() != b.GetHash());

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(g_usdsoq_supply.TotalMinted() == mintedBefore &&
                        g_usdsoq_supply.TotalBurned() == burnedBefore,
        "SOQ-I013: a REJECTED block moved the USDSOQ supply counters. The "
        "issuer's outstanding-supply figure would then disagree with the chain");
}

BOOST_AUTO_TEST_SUITE_END()
