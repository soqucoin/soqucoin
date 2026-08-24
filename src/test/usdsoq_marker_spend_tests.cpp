// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// usdsoq_marker_spend_tests.cpp — SOQ-I015, FIXED in b9b4ccd04. Regression
// guard for the rule that stops an ordinary transaction spending the USDSOQ
// authority marker.
//
// THE DEFECT, PAST TENSE
// ──────────────────────
// BTCSOQ forbids a non-authority spend of its v9 authority marker at three
// layers: ConnectBlock (bad-btcsoq-marker-spend), the ATMP mirror, and
// VerifyScript (SCRIPT_ERR_BTCSOQ_MARKER_SPEND). USDSOQ has no equivalent at
// any layer.
//
// The v5 spend path did not require authority:
//   * CheckInputs' authority skip needs an OP_5 *output*. A tx that spends the
//     marker without creating one does not take the skip, so its scripts run.
//   * VerifyScript routes v5 to EvalScript's USDSOQ handler, which validates
//     STRUCTURE ONLY — a 1-byte tag, a non-empty payload, at least one blob of
//     the right size, an authority-set item — and pushes true. Cryptographic
//     M-of-N verification deliberately lives in ConnectBlock, not here.
//   * ConnectBlock only M-of-N-verifies transactions that CREATE an OP_5
//     output. A tx that only SPENDS one is never verified by anybody.
//
// So the witness was fabricable from public data and the marker was spendable
// by anyone. Now rejected as bad-usdsoq-marker-spend at ConnectBlock, with an
// ATMP mirror so policy stays a strict subset of consensus.
//
// THE CONSEQUENCE, which is worse than losing 10000 sats
// ──────────────────────────────────────────────────────
// g_usdsoq_authority_outpoint is only advanced by authority transactions, so
// after an ordinary spend it still points at the now-SPENT marker. Every
// subsequent authority transaction must spend the tracked outpoint; none can,
// because the UTXO is gone. Observed failure is bad-txns-inputs-missingorspent
// — the transaction dies at input resolution, before any USDSOQ rule is even
// consulted. More direct than the predicted bad-usdsoq-authority-outpoint, and
// harder to recover from, because no USDSOQ code path is reached at all.
//
// USDSOQ mint, burn, freeze and unfreeze are dead from that block onward, for
// the cost of one ordinary transaction, by anyone. Recovery needs a code change
// or a reindex against a hand-set outpoint — not an on-chain operation, because
// every on-chain operation requires the marker that was just destroyed.
//
// Live on stagenet (USDSOQ active from height 0 with authority keys
// configured). Dormant on mainnet until activation.
//
// Credit: found by independent sweep of the USDSOQ/BTCSOQ asymmetry.

#include "chainparams.h"
#include "consensus/usdsoq.h"
#include "consensus/validation.h"
#include "test/dilithium_chain_setup.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

struct UsdsoqMarkerSetup : public DilithiumChainSetup {
    UsdsoqTestAuthority auth;

    CMutableTransaction BuildBootstrapAuthorityTx(const CTransaction& feeCoinbase)
    {
        const CAmount feeVal = feeCoinbase.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;
        CTxIn in;
        in.prevout = COutPoint(feeCoinbase.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);
        CTxOut mark; mark.nValue = 100000; mark.scriptPubKey = auth.MarkerSpk();
        tx.vout.push_back(mark);
        CTxOut chg; chg.nValue = feeVal - 110000; chg.scriptPubKey = Spk(OP_1);
        tx.vout.push_back(chg);
        SignInput(tx, 0, coinbaseSpk, feeVal);
        auth.Sign(tx, 0, auth.MarkerSpk());
        return tx;
    }

    //! An ORDINARY transaction that spends the authority marker and creates no
    //! OP_5 output. The v5 witness is fabricated from public data: nothing in
    //! it is secret and nothing is verified cryptographically on this path.
    CMutableTransaction BuildOrdinaryMarkerSpend(const COutPoint& marker,
                                                 CAmount markerVal,
                                                 const CTransaction& feeCoinbase)
    {
        const CAmount feeVal = feeCoinbase.vout[0].nValue;
        CMutableTransaction tx;
        tx.nVersion = 2;

        CTxIn mk; mk.prevout = marker; mk.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(mk);
        CTxIn fee; fee.prevout = COutPoint(feeCoinbase.GetHash(), 0);
        fee.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(fee);

        // Plain v1 payout. No OP_5 anywhere, so CheckInputs' authority skip does
        // not apply and ConnectBlock never treats this as an authority tx.
        CTxOut out;
        out.nValue = markerVal + feeVal - 20000;
        out.scriptPubKey = Spk(OP_1);
        tx.vout.push_back(out);

        SignInput(tx, 1, coinbaseSpk, feeVal);   // the fee input is honestly signed

        // Structural-only v5 witness: [tag, payload, blob, authority_set].
        std::vector<std::vector<unsigned char>>& w = tx.vin[0].scriptWitness.stack;
        w.clear();
        w.push_back(std::vector<unsigned char>{0x03});          // FREEZE tag
        w.push_back(std::vector<unsigned char>(8, 0xCD));       // non-empty payload
        w.push_back(std::vector<unsigned char>(2420, 0xEF));    // "signature", never verified
        w.push_back(std::vector<unsigned char>{0x00});          // authority_set
        return tx;
    }
};

BOOST_FIXTURE_TEST_SUITE(usdsoq_marker_spend_tests, UsdsoqMarkerSetup)

// ---------------------------------------------------------------------------
// THE DEFECT.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(an_ordinary_tx_must_not_spend_the_authority_marker)
{
    CMutableTransaction boot = BuildBootstrapAuthorityTx(coinbaseTxns[0]);
    CBlock b = CreateAndProcessBlock({boot}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == b.GetHash(),
        "the authority must exist before it can be destroyed");

    COutPoint marker(boot.GetHash(), 0);
    {
        LOCK(cs_main);
        BOOST_REQUIRE(g_usdsoq_authority_outpoint == marker);
    }

    CMutableTransaction steal = BuildOrdinaryMarkerSpend(marker, 100000, coinbaseTxns[1]);
    const std::string why = RejectReasonFor({steal});
    BOOST_TEST_MESSAGE("reject: '" << why << "'");

    BOOST_CHECK_MESSAGE(why == "bad-usdsoq-marker-spend",
        "SOQ-I015: an ordinary transaction spent the USDSOQ authority marker. "
        "BTCSOQ rejects this with bad-btcsoq-marker-spend at three layers; "
        "USDSOQ has no equivalent. The v5 witness above is fabricated from "
        "public data and is never cryptographically verified, because "
        "ConnectBlock only M-of-N-verifies transactions that CREATE an OP_5 "
        "output, and this one only spends one");
}

// ---------------------------------------------------------------------------
// THE CONSEQUENCE. Losing the marker output is trivial; losing the ability to
// ever run an authority operation again is not.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(destroying_the_marker_must_not_brick_the_authority)
{
    CMutableTransaction boot = BuildBootstrapAuthorityTx(coinbaseTxns[0]);
    CBlock b1 = CreateAndProcessBlock({boot}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());
    COutPoint marker(boot.GetHash(), 0);

    CMutableTransaction steal = BuildOrdinaryMarkerSpend(marker, 100000, coinbaseTxns[1]);
    CBlock b2 = CreateAndProcessBlock({steal}, coinbaseSpk);

    if (chainActive.Tip()->GetBlockHash() != b2.GetHash()) {
        BOOST_TEST_MESSAGE("marker spend was rejected — consequence not reachable");
        return;   // the primary test above already reports the defect
    }

    // The marker is gone but the tracker still points at it. Every authority
    // operation from here must spend an outpoint that no longer exists.
    CMutableTransaction nextAuth;
    nextAuth.nVersion = 2;
    CTxIn mk; mk.prevout = marker; mk.nSequence = CTxIn::SEQUENCE_FINAL;
    nextAuth.vin.push_back(mk);
    const CAmount feeVal = coinbaseTxns[2].vout[0].nValue;
    CTxIn fee; fee.prevout = COutPoint(coinbaseTxns[2].GetHash(), 0);
    fee.nSequence = CTxIn::SEQUENCE_FINAL; nextAuth.vin.push_back(fee);
    CTxOut mark; mark.nValue = 100000; mark.scriptPubKey = auth.MarkerSpk();
    nextAuth.vout.push_back(mark);
    CTxOut chg; chg.nValue = feeVal - 110000; chg.scriptPubKey = Spk(OP_1);
    nextAuth.vout.push_back(chg);
    SignInput(nextAuth, 1, coinbaseSpk, feeVal);
    auth.Sign(nextAuth, 0, auth.MarkerSpk());

    const std::string why = RejectReasonFor({nextAuth});
    BOOST_TEST_MESSAGE("post-destruction authority tx reject: '" << why << "'");

    BOOST_CHECK_MESSAGE(why.empty(),
        "SOQ-I015 consequence: after an ordinary transaction destroyed the "
        "marker, a correctly signed authority transaction is refused. USDSOQ "
        "mint/burn/freeze are dead from here on, for the price of one ordinary "
        "transaction, by anyone. Recovery is not an on-chain operation, because "
        "every on-chain operation needs the marker that was just destroyed");
}

BOOST_AUTO_TEST_SUITE_END()
