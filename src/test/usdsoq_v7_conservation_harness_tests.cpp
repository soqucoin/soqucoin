// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// usdsoq_v7_conservation_harness_tests.cpp — REAL consensus-path test for the
// v7 USDSOQ-holding asset-isolation property (CTxOut migration Phase 3).
//
// The VerifyScript-level tests (usdsoq_v7_holding_tests.cpp) prove a v7 holding
// SPENDS like a v1 key. They do NOT touch the per-asset conservation rule
// (validation.cpp SOQ-ARCH-002), which lives in ConnectBlock. This file drives
// that rule through actual block processing to pin the load-bearing value-safety
// property of routing IsUSDSOQ() onto the witness version (Phase 3-1):
//
//   A NON-authority tx must NOT be able to MINT USDSOQ by emitting a v7 output
//   from SOQ inputs. Because v7 is now USDSOQ-by-version, such a tx has
//   nUSDSOQIn=0 != nUSDSOQOut>0 → "bad-txns-usdsoq-not-conserved" → block rejected.
//
// Without the Phase-3 chokepoint recognising v7 as USDSOQ, this tx would conserve
// (0==0) and a v7 holding could be conjured from thin SOQ — silent infinite mint.
//
// Reuses the DilithiumChainSetup approach from freeze_registry_harness_tests.cpp
// (Dilithium v1 coinbase; TestChain240Setup's legacy P2PK is rejected by the
// Dilithium-only coinbase enforcement, dilithiumOnlyHeight=0 on regtest).

#include "chainparams.h"
#include "consensus/usdsoq.h"
#include "consensus/validation.h"
#include "key.h"
#include "miner.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "txdb.h"
#include "uint256.h"
#include "validation.h"
#include "crypto/sha256.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <algorithm>

namespace {

static const int COINBASE_MATURITY_SOQ = 60 * 4;  // 240, regtest

// V1 Dilithium single-key scriptPubKey: OP_1 <SHA256(rawPubkey)>.
static CScript MakeV1Spk(const std::vector<unsigned char>& rawPubkey)
{
    uint256 pkHash;
    CSHA256().Write(rawPubkey.data(), rawPubkey.size()).Finalize(pkHash.begin());
    CScript spk;
    spk << OP_1 << std::vector<unsigned char>(pkHash.begin(), pkHash.end());
    return spk;
}

// V7 USDSOQ-holding scriptPubKey: OP_7 <SHA256(rawPubkey)>. Same shape as v1, with
// OP_7 as the asset discriminator — IsUSDSOQ() is true purely by this version.
static CScript MakeV7Spk(const std::vector<unsigned char>& rawPubkey)
{
    uint256 pkHash;
    CSHA256().Write(rawPubkey.data(), rawPubkey.size()).Finalize(pkHash.begin());
    CScript spk;
    spk << OP_7 << std::vector<unsigned char>(pkHash.begin(), pkHash.end());
    return spk;
}

// 0x00-prefixed pubkey for the trailing witness item (FIPS 204 Table 3).
static std::vector<unsigned char> Prefixed(const std::vector<unsigned char>& rawPubkey)
{
    std::vector<unsigned char> out;
    out.reserve(rawPubkey.size() + 1);
    out.push_back(0x00);
    out.insert(out.end(), rawPubkey.begin(), rawPubkey.end());
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// Dilithium v1 chain fixture: mines 240 blocks with OP_1 <SHA256(pk)> coinbase
// so CreateNewBlock doesn't reject (dilithiumOnlyHeight=0 for regtest). USDSOQ is
// ALWAYS_ACTIVE on regtest (chainparams.cpp SOQ-AUD2-002), so the conservation
// rule is live. Distinct name from the freeze harness fixture to avoid an ODR clash.
// ---------------------------------------------------------------------------
struct V7ConservationChainSetup : public TestingSetup {
    CKey coinbaseKey;
    CScript coinbaseSpk;
    std::vector<unsigned char> coinbasePkBytes;
    std::vector<CTransaction> coinbaseTxns;

    V7ConservationChainSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        coinbaseKey.MakeNewKey(true);
        CPubKey pk = coinbaseKey.GetPubKey();           // local first — never .GetPubKey().begin() inline
        BOOST_REQUIRE(pk.IsValid());
        coinbasePkBytes.assign(pk.begin(), pk.end());
        BOOST_REQUIRE_EQUAL(coinbasePkBytes.size(), 1312u);
        coinbaseSpk = MakeV1Spk(coinbasePkBytes);
        BOOST_REQUIRE_EQUAL(coinbaseSpk.size(), 34u);

        for (int i = 0; i < COINBASE_MATURITY_SOQ; i++) {
            std::vector<CMutableTransaction> noTxns;
            CBlock b = CreateAndProcessBlock(noTxns, coinbaseSpk);
            BOOST_REQUIRE_MESSAGE(b.vtx.size() > 0, "block must have coinbase");
            coinbaseTxns.push_back(*b.vtx[0]);
        }
    }

    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& spk)
    {
        const CChainParams& cp = Params();
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(cp).CreateNewBlock(spk, true);
        BOOST_REQUIRE_MESSAGE(tmpl != nullptr, "CreateNewBlock must not return nullptr");
        CBlock& block = tmpl->block;
        block.vtx.resize(1);
        // Strip the stale witness commitment CreateNewBlock added for the empty
        // template, then let GenerateCoinbaseCommitment re-add one for our vtx set.
        {
            CMutableTransaction coinbaseMut(*block.vtx[0]);
            coinbaseMut.vout.erase(
                std::remove_if(coinbaseMut.vout.begin(), coinbaseMut.vout.end(),
                    [](const CTxOut& o) {
                        return o.scriptPubKey.size() >= 38 &&
                               o.scriptPubKey[0] == OP_RETURN &&
                               o.scriptPubKey[1] == 0x24 &&
                               o.scriptPubKey[2] == 0xaa &&
                               o.scriptPubKey[3] == 0x21 &&
                               o.scriptPubKey[4] == 0xa9 &&
                               o.scriptPubKey[5] == 0xed;
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
        std::shared_ptr<const CBlock> shared = std::make_shared<const CBlock>(block);
        bool fNewBlock = false;
        bool accepted = ProcessNewBlock(cp, shared, true, &fNewBlock);
        BOOST_TEST_MESSAGE("ProcessNewBlock: accepted=" << accepted << " fNewBlock=" << fNewBlock
            << " vtx=" << block.vtx.size() << " tip=" << chainActive.Tip()->GetBlockHash().ToString());
        return block;
    }

    // A NON-authority tx spending a mature coinbase to a single output `destSpk`,
    // signed with the Dilithium v1 witness path. Fee = 10000 sat in SOQ.
    CMutableTransaction BuildSpendTo(const CTransaction& coinbase, const CScript& destSpk)
    {
        CMutableTransaction tx;
        tx.nVersion = 2;
        const CAmount inVal = coinbase.vout[0].nValue;

        CTxIn in;
        in.prevout = COutPoint(coinbase.GetHash(), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);

        CTxOut out;
        out.nValue = inVal - 10000;
        out.scriptPubKey = destSpk;
        tx.vout.push_back(out);

        CTransaction ctxForSign(tx);
        uint256 sighash = SignatureHash(coinbaseSpk, ctxForSign, 0, SIGHASH_ALL,
                                         inVal, SIGVERSION_WITNESS_V0, nullptr);
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(coinbaseKey.Sign(sighash, sig));
        BOOST_REQUIRE_EQUAL(sig.size(), 2420u);
        sig.push_back((unsigned char)SIGHASH_ALL);

        tx.vin[0].scriptWitness.stack.clear();
        tx.vin[0].scriptWitness.stack.push_back(sig);
        tx.vin[0].scriptWitness.stack.push_back(Prefixed(coinbasePkBytes));
        return tx;
    }
};

BOOST_FIXTURE_TEST_SUITE(usdsoq_v7_conservation_harness_tests, V7ConservationChainSetup)

// ---------------------------------------------------------------------------
// LOAD-BEARING: a non-authority tx that emits a v7 USDSOQ output from SOQ inputs
// must be REJECTED — it would mint USDSOQ from nothing. nUSDSOQIn=0 != nUSDSOQOut>0
// → bad-txns-usdsoq-not-conserved. Proves the Phase-3 chokepoint (IsUSDSOQ→v7) is
// enforced inside ConnectBlock's conservation rule, not just at VerifyScript.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(v7_minted_from_soq_is_rejected)
{
    CKey recipient; recipient.MakeNewKey(true);
    CPubKey rpk = recipient.GetPubKey();                 // local first
    std::vector<unsigned char> rpkBytes(rpk.begin(), rpk.end());
    CScript v7 = MakeV7Spk(rpkBytes);
    BOOST_REQUIRE_EQUAL(v7.size(), 34u);
    BOOST_REQUIRE_EQUAL(v7[0], OP_7);

    CMutableTransaction conjure = BuildSpendTo(coinbaseTxns[0], v7);
    std::vector<CMutableTransaction> txns{conjure};
    CBlock B = CreateAndProcessBlock(txns, coinbaseSpk);

    // The block carrying the SOQ→v7 "mint" must NOT become the tip.
    BOOST_CHECK_MESSAGE(chainActive.Tip()->GetBlockHash() != B.GetHash(),
        "a non-authority SOQ-input → v7-USDSOQ-output tx must be rejected by conservation "
        "(can't conjure USDSOQ); if this connects, IsUSDSOQ() is not recognising v7");
}

// ---------------------------------------------------------------------------
// CONTROL: the identical machinery with a plain v1 SOQ output (no asset change)
// connects cleanly. Proves the rejection above is specifically the v7=USDSOQ
// classification tripping conservation, not a broken harness / signature.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(soq_to_soq_spend_connects)
{
    CKey recipient; recipient.MakeNewKey(true);
    CPubKey rpk = recipient.GetPubKey();                 // local first
    std::vector<unsigned char> rpkBytes(rpk.begin(), rpk.end());
    CScript v1 = MakeV1Spk(rpkBytes);

    CMutableTransaction soqSpend = BuildSpendTo(coinbaseTxns[0], v1);
    std::vector<CMutableTransaction> txns{soqSpend};
    CBlock B = CreateAndProcessBlock(txns, coinbaseSpk);

    BOOST_CHECK_MESSAGE(chainActive.Tip()->GetBlockHash() == B.GetHash(),
        "a conserving SOQ→SOQ spend must connect — confirms the v7 rejection is the asset rule, "
        "not a harness artifact");
}

BOOST_AUTO_TEST_SUITE_END()
