// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// connectblock_txdata_lifetime_tests.cpp — ConnectBlock keeps the precomputed
// transaction data alive until the queued script checks have finished.
//
// ConnectBlock hands each transaction's script checks to the check queue, and
// each check holds a pointer into ConnectBlock's vector of
// PrecomputedTransactionData. When a later transaction in the block fails,
// ConnectBlock returns before it waits on the queue, and the destructor of the
// queue control finishes the checks still queued. Locals are destroyed in
// reverse order of declaration, so the vector is declared before the control
// (Bitcoin Core PR #35209).
//
// In a build with -fsanitize=address, the case fails when the vector is
// declared after the control: the sanitizer reports a read of freed memory
// from a script check.

#include "test/dilithium_chain_setup.h"

#include <boost/test/unit_test.hpp>

namespace {

//! Enough ML-DSA-44 inputs that checks are still queued, while the worker
//! threads run, when ConnectBlock reaches the failing transaction. An input is
//! about 3,900 weight units, so the block stays far below MAX_BLOCK_WEIGHT.
const unsigned int SPEND_INPUTS = 200;
const CAmount SEED_VALUE = 10 * COIN;
const CAmount SPEND_FEE = 100000;

} // namespace

struct TxdataLifetimeSetup : public DilithiumChainSetup {
    //! One transaction spending `n` seeded v1 coins, every input signed.
    CMutableTransaction SignedSpend(unsigned int n)
    {
        CMutableTransaction tx;
        tx.nVersion = 2;
        for (unsigned int i = 0; i < n; i++) {
            CTxIn in;
            in.prevout = SeedCoin(coinbaseSpk, SEED_VALUE, (uint8_t)(i + 1));
            in.nSequence = CTxIn::SEQUENCE_FINAL;
            tx.vin.push_back(in);
        }
        CTxOut out;
        out.nValue = n * SEED_VALUE - SPEND_FEE;
        out.scriptPubKey = coinbaseSpk;
        tx.vout.push_back(out);
        for (unsigned int i = 0; i < n; i++)
            SignInput(tx, i, coinbaseSpk, SEED_VALUE);
        return tx;
    }

    //! A signed transaction whose only input does not exist.
    CMutableTransaction MissingInputSpend()
    {
        uint256 txid;
        txid.begin()[31] = 0x01;   // SeedCoin sets only the first byte
        CMutableTransaction tx;
        tx.nVersion = 2;
        CTxIn in;
        in.prevout = COutPoint(txid, 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);
        CTxOut out;
        out.nValue = SEED_VALUE - SPEND_FEE;
        out.scriptPubKey = coinbaseSpk;
        tx.vout.push_back(out);
        SignInput(tx, 0, coinbaseSpk, SEED_VALUE);
        return tx;
    }
};

BOOST_FIXTURE_TEST_SUITE(connectblock_txdata_lifetime_tests, TxdataLifetimeSetup)

BOOST_AUTO_TEST_CASE(block_failing_after_queued_checks)
{
    BOOST_REQUIRE_MESSAGE(nScriptCheckThreads > 0,
        "the check queue must be in use, or ConnectBlock runs every check inline");

    // After the coinbase, the block holds the spend, whose checks are queued,
    // and then a transaction whose input does not exist.
    const CMutableTransaction spend = SignedSpend(SPEND_INPUTS);
    const CMutableTransaction missing = MissingInputSpend();

    // The block as a peer would send it, with the worker threads running:
    // ProcessNewBlock stores it, ConnectBlock queues the spend's checks and
    // fails on the next transaction, and the tip does not move. AcceptBlock
    // stores a block only after CheckBlock and ContextualCheckBlock pass, so
    // a stored block marked failed is one that failed to connect.
    const uint256 tipBefore = chainActive.Tip()->GetBlockHash();
    const CBlock block = CreateAndProcessBlock({spend, missing}, coinbaseSpk);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == tipBefore);
    {
        LOCK(cs_main);
        BlockMap::const_iterator it = mapBlockIndex.find(block.GetHash());
        BOOST_REQUIRE(it != mapBlockIndex.end());
        BOOST_CHECK(it->second->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK(it->second->nStatus & BLOCK_FAILED_VALID);
    }

    // With the worker threads stopped, every check queued for the spend is
    // still queued when ConnectBlock returns, so the control's destructor runs
    // all of them. TestBlockValidity also gives the reject reason: the input
    // check of the transaction after the spend.
    threadGroup.interrupt_all();
    threadGroup.join_all();
    BOOST_CHECK_EQUAL(RejectReasonFor({spend, missing}), "bad-txns-inputs-missingorspent");

    // The controls run last because they fill the signature cache. The spend
    // alone is valid, so each of its queued checks runs to the end. With one
    // signature changed the block fails with no reject reason, which is how
    // ConnectBlock reports a failed queued check, so script checks are not
    // skipped in this setup.
    BOOST_CHECK(BlockIsValid({spend}));
    CMutableTransaction altered = spend;
    altered.vin[0].scriptWitness.stack[0][0] ^= 0x01;
    BOOST_CHECK(!BlockIsValid({altered}));
    BOOST_CHECK_EQUAL(RejectReasonFor({altered}), "");
}

BOOST_AUTO_TEST_SUITE_END()
