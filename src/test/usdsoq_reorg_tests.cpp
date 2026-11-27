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
#include "init.h"
#include "test/dilithium_chain_setup.h"
#include "txdb.h"
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

// ---------------------------------------------------------------------------
// SOQ-I014. VerifyDB runs at EVERY startup (DEFAULT_CHECKLEVEL=3,
// DEFAULT_CHECKBLOCKS=6) and calls DisconnectBlock on the last N blocks against
// a SCRATCH coins view, passing pfClean. Only level 4 reconnects, so at the
// default the blocks are never re-applied.
//
// The coins changes land in the scratch view and are discarded. The asset
// reversals do not: they mutate the process globals and write straight to
// pcoinsdbview. So an ordinary restart rewinds USDSOQ/BTCSOQ supply counters,
// the authority outpoint, the freeze registry and the minted-deposit set by up
// to six blocks, permanently, and never puts them back.
//
// This was seen once already and mis-diagnosed. SOQ-HOTFIX-002 (init.cpp)
// records the June 15 2026 Broadcast VPS crash loop — 360 restarts in three
// hours — caused by UndoMint failing against a still-zeroed counter. The fix
// was to load the globals BEFORE VerifyDB so UndoMint would succeed. That
// removed the crash, which was the only thing making the corruption visible.
//
// pfClean already distinguishes the two callers: DisconnectTip passes nullptr,
// VerifyDB passes &fClean. That is the signal the asset reversals should be
// gated on.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(a_verification_disconnect_must_not_mutate_asset_state)
{
    CMutableTransaction boot = BuildBootstrapAuthorityTx(coinbaseTxns[0]);
    CBlock b = CreateAndProcessBlock({boot}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b.GetHash());

    COutPoint trackedBefore;
    {
        LOCK(cs_main);
        trackedBefore = g_usdsoq_authority_outpoint;
        BOOST_REQUIRE_MESSAGE(!trackedBefore.IsNull(),
            "the authority tracker must be set before this proves anything");
    }

    // Exactly what VerifyDB does at nCheckLevel 3: disconnect into a SCRATCH
    // view, passing pfClean, and never reconnect.
    {
        LOCK(cs_main);
        CCoinsViewCache scratch(pcoinsTip);
        CValidationState state;
        bool fClean = true;
        BlockMap::iterator it = mapBlockIndex.find(b.GetHash());
        BOOST_REQUIRE(it != mapBlockIndex.end());
        CBlock disk;
        BOOST_REQUIRE(ReadBlockFromDisk(disk, it->second, Params().GetConsensus(0)));
        DisconnectBlock(disk, state, it->second, scratch, &fClean);
        // scratch is discarded here, exactly as VerifyDB discards it.
    }

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(g_usdsoq_authority_outpoint == trackedBefore,
        "SOQ-I014: a VERIFICATION disconnect (pfClean != nullptr, scratch coins "
        "view, never reconnected) rewound the USDSOQ authority tracker. VerifyDB "
        "does this at every startup for the last 6 blocks, so an ordinary "
        "restart silently desynchronises asset state from the chain. Gate the "
        "asset reversals on pfClean == nullptr");
}

// ---------------------------------------------------------------------------
// The order of the two supply reversals. ConnectBlock applies a block's mint
// and then its burn. UndoMint refuses to leave the minted total below the
// burned total, so a block that mints and burns more than was outstanding
// before it can be disconnected only if its burn is taken back first.
// ---------------------------------------------------------------------------
struct UsdsoqMintAndBurnSetup : public UsdsoqReorgSetup {
    const CAmount V = 1000 * COIN;

    //! An issuer transaction minting v7Val of the token to the fixture's key:
    //! the marker at output 0, the token at output 1, the change at output 2.
    //! With prevMarker it spends that marker at input 0 and coinbase n at
    //! input 1; without, it is the bootstrap and spends coinbase n alone.
    CMutableTransaction Mint(size_t n, CAmount v7Val, const COutPoint* prevMarker = nullptr)
    {
        const CTransaction& cb = coinbaseTxns[n];
        const CAmount fund = cb.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;
        if (prevMarker)
            tx.vin.push_back(CTxIn(*prevMarker, CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vin.push_back(CTxIn(COutPoint(cb.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vout.push_back(CTxOut(10000, auth.MarkerSpk()));
        tx.vout.push_back(CTxOut(v7Val, Spk(OP_7)));
        tx.vout.push_back(CTxOut(fund - 20000, coinbaseSpk));
        SignInput(tx, prevMarker ? 1 : 0, coinbaseSpk, fund);
        auth.Sign(tx, 0, auth.MarkerSpk());
        return tx;
    }

    //! An issuer transaction spending the marker and the token output of
    //! `mint`, with coinbase n for the fee: it burns v7Val and mints nothing.
    CMutableTransaction Burn(const CMutableTransaction& mint, size_t n, CAmount v7Val)
    {
        const CTransaction& cb = coinbaseTxns[n];
        const CAmount fund = cb.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(COutPoint(mint.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vin.push_back(CTxIn(COutPoint(cb.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vin.push_back(CTxIn(COutPoint(mint.GetHash(), 1), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vout.push_back(CTxOut(10000, auth.MarkerSpk()));
        tx.vout.push_back(CTxOut(fund - 10000, coinbaseSpk));
        SignInput(tx, 1, coinbaseSpk, fund);
        SignInput(tx, 2, Spk(OP_7), v7Val);
        auth.Sign(tx, 0, auth.MarkerSpk());
        return tx;
    }

    CBlockIndex* Tip()
    {
        LOCK(cs_main);
        return chainActive.Tip();
    }

    //! Connects a block of txns on the tip and returns its index.
    CBlockIndex* Connect(const std::vector<CMutableTransaction>& txns)
    {
        const CBlock b = CreateAndProcessBlock(txns, coinbaseSpk);
        LOCK(cs_main);
        BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == b.GetHash(), "the block did not connect");
        return chainActive.Tip();
    }

    bool Invalidate(CBlockIndex* index)
    {
        LOCK(cs_main);
        CValidationState state;
        const bool done = InvalidateBlock(state, Params(), index);
        mempool.clear();
        return done;
    }

    //! A branch of `length` empty blocks on the tip, set aside with
    //! InvalidateBlock so that the next block connects on the same parent.
    std::vector<CBlockIndex*> SetAsideABranch(int length)
    {
        std::vector<CBlockIndex*> branch;
        for (int i = 0; i < length; ++i)
            branch.push_back(Connect({}));
        BOOST_REQUIRE(Invalidate(branch.front()));
        BOOST_REQUIRE(Tip() == branch.front()->pprev);
        return branch;
    }

    //! Makes a block set aside valid again; the node moves to the most work.
    bool Reconsider(CBlockIndex* index)
    {
        {
            LOCK(cs_main);
            BOOST_REQUIRE(ResetBlockFailureFlags(index));
        }
        CValidationState state;
        return ActivateBestChain(state, Params());
    }

    //! The totals, in memory and in the database view.
    void CheckTotals(CAmount minted, CAmount burned)
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(g_usdsoq_supply.TotalMinted(), minted);
        BOOST_CHECK_EQUAL(g_usdsoq_supply.TotalBurned(), burned);
        CUSDSOQSupply stored;
        BOOST_CHECK(pcoinsdbview->ReadUSDSOQSupply(stored));
        BOOST_CHECK_EQUAL(stored.TotalMinted(), minted);
        BOOST_CHECK_EQUAL(stored.TotalBurned(), burned);
    }

    //! The totals and the tracked marker, in memory and in the database view.
    void CheckTokenState(CAmount minted, CAmount burned, const COutPoint& marker)
    {
        CheckTotals(minted, burned);
        LOCK(cs_main);
        BOOST_CHECK(g_usdsoq_authority_outpoint == marker);
        COutPoint storedMarker;
        BOOST_CHECK(pcoinsdbview->ReadUSDSOQAuthorityOutpoint(storedMarker));
        BOOST_CHECK(storedMarker == marker);
    }
};

// A block holds an issuer mint and the burn of what it mints, with nothing
// outstanding before it, and the node leaves it for a longer branch built on
// its parent.
BOOST_FIXTURE_TEST_CASE(a_block_that_mints_and_burns_it_is_left_for_a_longer_branch, UsdsoqMintAndBurnSetup)
{
    CBlockIndex* parent = Tip();
    const std::vector<CBlockIndex*> longer = SetAsideABranch(2);
    const CMutableTransaction mint = Mint(0, V);
    const CMutableTransaction burn = Burn(mint, 1, V);
    CBlockIndex* block = Connect({mint, burn});
    CheckTokenState(V, V, COutPoint(burn.GetHash(), 0));

    BOOST_CHECK(Reconsider(longer.front()));
    BOOST_CHECK(Tip() == longer.back());
    {
        LOCK(cs_main);
        BOOST_CHECK(!chainActive.Contains(block));
        BOOST_CHECK(chainActive.Contains(parent));
    }
    CheckTokenState(0, 0, COutPoint());
    BOOST_CHECK(!ShutdownRequested());
}

// The same block given to InvalidateBlock, which disconnects it through the
// DisconnectTip that a reorganisation calls.
BOOST_FIXTURE_TEST_CASE(a_block_that_mints_and_burns_it_is_invalidated, UsdsoqMintAndBurnSetup)
{
    CBlockIndex* parent = Tip();
    const CMutableTransaction mint = Mint(0, V);
    const CMutableTransaction burn = Burn(mint, 1, V);
    CBlockIndex* block = Connect({mint, burn});
    CheckTokenState(V, V, COutPoint(burn.GetHash(), 0));

    BOOST_CHECK(Invalidate(block));
    BOOST_CHECK(Tip() == parent);
    CheckTokenState(0, 0, COutPoint());
    BOOST_CHECK(!ShutdownRequested());
}

// Totals above zero before the block, and a burn larger than what was
// outstanding before it: the block mints 2V on the marker of an earlier mint
// of V and burns the 2V.
BOOST_FIXTURE_TEST_CASE(a_burn_larger_than_what_was_outstanding_is_taken_back_first, UsdsoqMintAndBurnSetup)
{
    const CMutableTransaction first = Mint(0, V);
    Connect({first});
    const COutPoint firstMarker(first.GetHash(), 0);
    CheckTokenState(V, 0, firstMarker);

    CBlockIndex* parent = Tip();
    const CMutableTransaction mint = Mint(1, 2 * V, &firstMarker);
    const CMutableTransaction burn = Burn(mint, 2, 2 * V);
    CBlockIndex* block = Connect({mint, burn});
    CheckTokenState(3 * V, 2 * V, COutPoint(burn.GetHash(), 0));

    BOOST_CHECK(Invalidate(block));
    BOOST_CHECK(Tip() == parent);
    CheckTokenState(V, 0, firstMarker);
    BOOST_CHECK(!ShutdownRequested());
}

// Both totals above zero before the block: an earlier mint of V is burned in
// full, which leaves (V, V). The block mints V/2 on the marker of that burn
// and burns it, more than was outstanding before it.
BOOST_FIXTURE_TEST_CASE(a_block_that_mints_and_burns_it_after_a_full_burn_is_invalidated, UsdsoqMintAndBurnSetup)
{
    const CMutableTransaction first = Mint(0, V);
    Connect({first});
    const CMutableTransaction burnAll = Burn(first, 1, V);
    CBlockIndex* parent = Connect({burnAll});
    const COutPoint priorMarker(burnAll.GetHash(), 0);
    CheckTokenState(V, V, priorMarker);

    const CMutableTransaction mint = Mint(2, V / 2, &priorMarker);
    const CMutableTransaction burn = Burn(mint, 3, V / 2);
    CBlockIndex* block = Connect({mint, burn});
    CheckTokenState(V + V / 2, V + V / 2, COutPoint(burn.GetHash(), 0));

    BOOST_CHECK(Invalidate(block));
    BOOST_CHECK(Tip() == parent);
    CheckTokenState(V, V, priorMarker);
    BOOST_CHECK(!ShutdownRequested());
}

// The block made valid again after its disconnection connects with the
// totals and the marker of its first connection.
BOOST_FIXTURE_TEST_CASE(a_block_that_mints_and_burns_it_connects_again, UsdsoqMintAndBurnSetup)
{
    const CMutableTransaction mint = Mint(0, V);
    const CMutableTransaction burn = Burn(mint, 1, V);
    CBlockIndex* block = Connect({mint, burn});
    BOOST_CHECK(Invalidate(block));

    BOOST_CHECK(Reconsider(block));
    BOOST_CHECK(Tip() == block);
    CheckTokenState(V, V, COutPoint(burn.GetHash(), 0));
}

BOOST_FIXTURE_TEST_CASE(a_block_with_a_mint_alone_is_invalidated, UsdsoqMintAndBurnSetup)
{
    CBlockIndex* parent = Tip();
    const CMutableTransaction mint = Mint(0, V);
    CBlockIndex* block = Connect({mint});
    CheckTokenState(V, 0, COutPoint(mint.GetHash(), 0));

    BOOST_CHECK(Invalidate(block));
    BOOST_CHECK(Tip() == parent);
    CheckTokenState(0, 0, COutPoint());
}

BOOST_FIXTURE_TEST_CASE(a_block_with_a_burn_alone_is_invalidated, UsdsoqMintAndBurnSetup)
{
    const CMutableTransaction mint = Mint(0, V);
    Connect({mint});
    const COutPoint mintMarker(mint.GetHash(), 0);
    CBlockIndex* parent = Tip();
    const CMutableTransaction burn = Burn(mint, 1, V);
    CBlockIndex* block = Connect({burn});
    CheckTokenState(V, V, COutPoint(burn.GetHash(), 0));

    BOOST_CHECK(Invalidate(block));
    BOOST_CHECK(Tip() == parent);
    CheckTokenState(V, 0, mintMarker);
}

// The control: the same mint and burn in two blocks, left for a longer branch.
BOOST_FIXTURE_TEST_CASE(the_mint_and_the_burn_in_two_blocks_are_left_for_a_longer_branch, UsdsoqMintAndBurnSetup)
{
    const std::vector<CBlockIndex*> longer = SetAsideABranch(3);
    const CMutableTransaction mint = Mint(0, V);
    const CMutableTransaction burn = Burn(mint, 1, V);
    Connect({mint});
    Connect({burn});
    CheckTokenState(V, V, COutPoint(burn.GetHash(), 0));

    BOOST_CHECK(Reconsider(longer.front()));
    BOOST_CHECK(Tip() == longer.back());
    CheckTokenState(0, 0, COutPoint());
    BOOST_CHECK(!ShutdownRequested());
}

// A node that holds the totals a disconnection in the earlier order left: its
// first attempt refused UndoMint, ran UndoBurn and wrote (V, 0) with the block
// still the tip. From (V, 0) the burn cannot be taken back and the mint is,
// which leaves (0, 0); from (0, 0) both are refused. Either way the block
// stays the tip.
BOOST_FIXTURE_TEST_CASE(totals_left_by_the_earlier_order_keep_the_block, UsdsoqMintAndBurnSetup)
{
    const CMutableTransaction mint = Mint(0, V);
    const CMutableTransaction burn = Burn(mint, 1, V);
    CBlockIndex* block = Connect({mint, burn});
    {
        LOCK(cs_main);
        BOOST_REQUIRE(g_usdsoq_supply.UndoBurn(V));
        BOOST_REQUIRE(pcoinsdbview->WriteUSDSOQSupply(g_usdsoq_supply));
    }
    CheckTotals(V, 0);

    BOOST_CHECK(!Invalidate(block));
    BOOST_CHECK(Tip() == block);
    CheckTotals(0, 0);

    BOOST_CHECK(!Invalidate(block));
    BOOST_CHECK(Tip() == block);
    CheckTotals(0, 0);
}

BOOST_AUTO_TEST_SUITE_END()
