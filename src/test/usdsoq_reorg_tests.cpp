// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// usdsoq_reorg_tests.cpp — SOQ-I012. Disconnecting the BOOTSTRAP authority
// transaction must return the tracked authority outpoint to NULL.
//
// THE DEFECT
// ──────────
// ConnectBlock's bootstrap path sets g_usdsoq_authority_outpoint and writes it
// through to LevelDB. DisconnectBlock's reversal only knew how to revert to a
// PRIOR marker input, so when the disconnected tx was the bootstrap — which by
// definition spends no prior authority outpoint — the loop found nothing and
// left the tracker pointing at the disconnected block's marker. An outpoint
// that now exists on no chain.
//
// ConnectBlock then sees a NON-null tracked outpoint, finds no input spending
// it, and rejects the replacement block with bad-usdsoq-authority-outpoint. The
// node forks itself off the network, and because the tracker is persisted a
// restart does not clear it — recovery is -reindex.
//
// WHY IT MATTERS AND WHEN
// ───────────────────────
// Dormant today: v5 outputs cannot be created before activation (SOQ-I009), so
// no authority tx can exist on mainnet. It becomes live the day USDSOQ
// activates, because the FIRST authority tx after activation is a bootstrap and
// a one-block reorg is entirely routine. SOQ-I008 sharpened it: the old
// hardcoded 54300 meant a fresh mainnet skipped the outpoint-chain rule for its
// first 54,300 blocks, which accidentally cushioned this. Enforcement now runs
// from height 0.
//
// HOW IT SURVIVED
// ───────────────
// It was FOUND. The BTCSOQ 2D review hit the identical gap, fixed the BTCSOQ
// side, and recorded the USDSOQ side in a code comment reading "the USDSOQ
// reversal inherits this gap". A known defect written as prose, in a comment on
// a different subsystem, with no bead and no test. It stayed unfixed.
//
// That is the whole reason this file exists rather than a comment saying the
// same thing again.

#include "chainparams.h"
#include "consensus/usdsoq.h"
#include "consensus/validation.h"
#include "test/dilithium_chain_setup.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

struct UsdsoqReorgSetup : public DilithiumChainSetup {
    UsdsoqTestAuthority auth;

    //! A BOOTSTRAP authority tx: it carries the OP_5 marker but spends no prior
    //! authority outpoint, because none exists yet. Input 0 carries the M-of-N
    //! witness, which is where ConnectBlock's bootstrap path looks.
    CMutableTransaction BuildBootstrapAuthorityTx(const CTransaction& feeCoinbase)
    {
        const CAmount feeVal = feeCoinbase.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;

        CTxIn in;
        in.prevout = COutPoint(feeCoinbase.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);

        CTxOut mark;
        mark.nValue = 10000;
        mark.scriptPubKey = auth.MarkerSpk();
        tx.vout.push_back(mark);

        CTxOut chg;
        chg.nValue = feeVal - 20000;
        chg.scriptPubKey = Spk(OP_1);
        tx.vout.push_back(chg);

        SignInput(tx, 0, coinbaseSpk, feeVal);
        auth.Sign(tx, 0, auth.MarkerSpk());   // overwrites input 0's witness
        return tx;
    }

    void ReorgOut(const CBlock& b)
    {
        LOCK(cs_main);
        CValidationState state;
        BlockMap::iterator it = mapBlockIndex.find(b.GetHash());
        BOOST_REQUIRE(it != mapBlockIndex.end());
        InvalidateBlock(state, Params(), it->second);
        ActivateBestChain(state, Params());
    }
};

BOOST_FIXTURE_TEST_SUITE(usdsoq_reorg_tests, UsdsoqReorgSetup)

// ---------------------------------------------------------------------------
// The defect itself, at the level of the tracked global.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(disconnecting_the_bootstrap_returns_the_outpoint_to_null)
{
    {
        LOCK(cs_main);
        BOOST_REQUIRE_MESSAGE(g_usdsoq_authority_outpoint.IsNull(),
            "fixture must start with no tracked authority outpoint");
    }

    CMutableTransaction boot = BuildBootstrapAuthorityTx(coinbaseTxns[0]);
    CBlock b = CreateAndProcessBlock({boot}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == b.GetHash(),
        "the bootstrap authority block must connect first, or this proves nothing");

    {
        LOCK(cs_main);
        BOOST_REQUIRE_MESSAGE(!g_usdsoq_authority_outpoint.IsNull(),
            "ConnectBlock must have advanced the tracker to the new marker");
        BOOST_CHECK_EQUAL(g_usdsoq_authority_outpoint.hash.ToString(),
                          boot.GetHash().ToString());
    }

    ReorgOut(b);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() != b.GetHash());

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(g_usdsoq_authority_outpoint.IsNull(),
        "SOQ-I012: after disconnecting the BOOTSTRAP authority tx the tracked "
        "outpoint must be NULL. Leaving it pointing at the disconnected block's "
        "marker means ConnectBlock will reject the replacement block with "
        "bad-usdsoq-authority-outpoint and the node forks itself off the network");
}

// ---------------------------------------------------------------------------
// The consequence, which is what actually matters. Checking the global is
// necessary but not sufficient — the property under test is that the node is
// still able to accept the chain everyone else is on.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(a_replacement_bootstrap_is_accepted_after_the_reorg)
{
    CMutableTransaction boot = BuildBootstrapAuthorityTx(coinbaseTxns[0]);
    CBlock b = CreateAndProcessBlock({boot}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b.GetHash());

    ReorgOut(b);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() != b.GetHash());

    // A different coinbase, so this is a genuinely new bootstrap tx rather than
    // a resubmission of the one that was just disconnected.
    CMutableTransaction boot2 = BuildBootstrapAuthorityTx(coinbaseTxns[1]);
    BOOST_CHECK_MESSAGE(RejectReasonFor({boot2}).empty(),
        "SOQ-I012: a replacement bootstrap authority tx must be acceptable after "
        "the first one was reorged out. If this returns "
        "bad-usdsoq-authority-outpoint, the node is wedged against a phantom "
        "outpoint and only -reindex recovers it");
}

// ---------------------------------------------------------------------------
// Guard on the non-bootstrap path, so the fix cannot regress into "always null
// the tracker on any disconnect" — which would be a different bug wearing the
// same shape.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(disconnecting_a_chained_authority_tx_restores_the_prior_marker)
{
    CMutableTransaction boot = BuildBootstrapAuthorityTx(coinbaseTxns[0]);
    CBlock b1 = CreateAndProcessBlock({boot}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());

    COutPoint bootMarker(boot.GetHash(), 0);

    // A chained authority tx: spends the tracked marker, emits a new one.
    CMutableTransaction next;
    next.nVersion = 2;
    CTxIn mk; mk.prevout = bootMarker; mk.nSequence = CTxIn::SEQUENCE_FINAL;
    next.vin.push_back(mk);
    const CAmount feeVal = coinbaseTxns[1].vout[0].nValue;
    CTxIn fee; fee.prevout = COutPoint(coinbaseTxns[1].GetHash(), 0);
    fee.nSequence = CTxIn::SEQUENCE_FINAL; next.vin.push_back(fee);
    CTxOut mark; mark.nValue = 10000; mark.scriptPubKey = auth.MarkerSpk();
    next.vout.push_back(mark);
    CTxOut chg; chg.nValue = feeVal - 20000; chg.scriptPubKey = Spk(OP_1);
    next.vout.push_back(chg);
    SignInput(next, 1, coinbaseSpk, feeVal);
    auth.Sign(next, 0, auth.MarkerSpk());

    CBlock b2 = CreateAndProcessBlock({next}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == b2.GetHash(),
        "the chained authority block must connect, or the control proves nothing");

    ReorgOut(b2);

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(g_usdsoq_authority_outpoint == bootMarker,
        "disconnecting a CHAINED authority tx must restore the PRIOR marker, not "
        "null the tracker. Nulling here would send a live chain back to the "
        "bootstrap path and orphan the real authority UTXO");
}

BOOST_AUTO_TEST_SUITE_END()
