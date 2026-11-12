// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2020-2022 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/validation.h"
#include "key.h"
#include "validation.h"
#include "miner.h"
#include "pubkey.h"
#include "txmempool.h"
#include "random.h"
#include "script/standard.h"
#include "test/dilithium_chain_setup.h"
#include "test/test_bitcoin.h"
#include "utiltime.h"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(tx_validationcache_tests)

static bool
ToMemPool(CMutableTransaction& tx)
{
    LOCK(cs_main);

    CValidationState state;
    return AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), false, NULL, NULL, true, 0);
}

// The chain is DilithiumChainSetup's: regtest requires a witness v1 coinbase
// from height 0, so the spends are v1 spends with ML-DSA-44 signatures.
BOOST_FIXTURE_TEST_CASE(tx_mempool_block_doublespend, DilithiumChainSetup)
{
    // Make sure skipping validation of transactions that were
    // validated going into the memory pool does not allow
    // double-spends in blocks to pass validation when they should not.

    // Create a double-spend of mature coinbase txn: two transactions with
    // different outputs, each signed for the same coinbase output.
    const CAmount cbValue = coinbaseTxns[0].vout[0].nValue;
    std::vector<CMutableTransaction> spends;
    spends.resize(2);
    for (int i = 0; i < 2; i++)
    {
        spends[i].nVersion = 1;
        spends[i].vin.resize(1);
        spends[i].vin[0].prevout.hash = coinbaseTxns[0].GetHash();
        spends[i].vin[0].prevout.n = 0;
        spends[i].vout.resize(1);
        spends[i].vout[0].nValue = (i + 1) * COIN;
        spends[i].vout[0].scriptPubKey = coinbaseSpk;

        // Sign:
        SignInput(spends[i], 0, coinbaseSpk, cbValue);
    }
    BOOST_REQUIRE(spends[0].GetHash() != spends[1].GetHash());
    std::vector<CMutableTransaction> oneSpend;
    oneSpend.push_back(spends[0]);

    // The blocks are built while the mempool is empty: a block template commits
    // to the transactions it was assembled from. Each spend is valid in a block
    // of its own, so a refusal below is the refusal of the second spend.
    BOOST_REQUIRE_EQUAL(mempool.size(), 0U);
    BOOST_CHECK(BlockIsValid(oneSpend));
    BOOST_CHECK(BlockIsValid(std::vector<CMutableTransaction>(1, spends[1])));
    const CBlock both = BuildSolvedBlock(spends, coinbaseSpk);
    const CBlock first = BuildSolvedBlock(oneSpend, coinbaseSpk);
    BOOST_REQUIRE(both.GetHash() != first.GetHash());

    // The reject reason of a block on the current tip, "" when it validates.
    auto rejectReason = [](const CBlock& b) -> std::string {
        LOCK(cs_main);
        CValidationState st;
        if (TestBlockValidity(st, Params(), b, chainActive.Tip(), true, true))
            return std::string();
        return st.GetRejectReason();
    };
    auto process = [](const CBlock& b) {
        std::shared_ptr<const CBlock> shared = std::make_shared<const CBlock>(b);
        ProcessNewBlock(Params(), shared, true, NULL);
    };
    const std::string doubleSpend = "bad-txns-inputs-missingorspent";
    const uint256 tipBefore = chainActive.Tip()->GetBlockHash();

    // Test 1: block with both of those transactions should be rejected.
    BOOST_CHECK_EQUAL(rejectReason(both), doubleSpend);

    // Test 2: ... and should be rejected if spend1 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[0]));
    BOOST_CHECK_EQUAL(rejectReason(both), doubleSpend);
    mempool.clear();

    // Test 3: ... and should be rejected if spend2 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[1]));
    BOOST_CHECK_EQUAL(rejectReason(both), doubleSpend);
    process(both);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == tipBefore);
    BOOST_CHECK_EQUAL(mempool.size(), 1U);

    // Final sanity test: second spend in mempool, first in block, that's OK:
    BOOST_CHECK_EQUAL(rejectReason(first), "");
    process(first);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == first.GetHash());
    // spends[1] should have been removed from the mempool when the
    // block with spends[0] is accepted:
    BOOST_CHECK_EQUAL(mempool.size(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
