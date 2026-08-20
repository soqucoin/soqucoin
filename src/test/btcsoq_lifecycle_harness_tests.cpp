// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// btcsoq_lifecycle_harness_tests.cpp — REAL consensus-path proof of the
// BTCSOQ money-path (Steps 2C/2D). Drives actual ConnectBlock / DisconnectBlock
// through the validation engine on a regtest chain, with real ML-DSA-44
// authority keypairs, exercising:
//   * bootstrap MINT bound to a Bitcoin deposit (v9 marker + signed OP_RETURN
//     op envelope + v8 output; supply counter moves; deposit recorded)
//   * a plain v8 TRANSFER (non-authority, conserves value, spent via the
//     audited v1 Dilithium path now that SCRIPT_VERIFY_BTCSOQ gates v8)
//   * an authority BURN (v8 input destroyed, release intent == burned sats,
//     supply decremented)
//   * reorg UNDO (supply reversal + minted-deposit erase so the same deposit
//     can re-mint on the new chain)
//   * double-mint REJECTION (the same btc_txid:vout cannot back two mints)
//
// Mirrors the freeze_registry_harness_tests fixture (Dilithium v1 coinbase so
// CreateNewBlock's dilithium-only coinbase rule is satisfied on regtest).

#include "chainparams.h"
#include "consensus/btcsoq.h"
#include "consensus/usdsoq.h"     // ComputeAuthorityKeyHash, DILITHIUM_* sizes
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
#include "coins.h"
#include "test/test_bitcoin.h"
#include "test/testutil.h"   // ScopedRegtestActivation

extern "C" {
#include "crypto/dilithium/api.h"
}

#include <boost/test/unit_test.hpp>
#include <algorithm>

namespace {

static const int COINBASE_MATURITY_SOQ = 60 * 4;  // 240, regtest
static const CAmount MINT_SATS = 1000000;          // above the UTXO-cost floor

// Raw ML-DSA-44 keypair (matches CBTCSOQAuthority::VerifyAuthoritySignatures,
// which calls pqcrystals_dilithium2_ref_verify with an empty context).
struct AuthKey {
    std::vector<uint8_t> pk, sk;
    AuthKey() : pk(pqcrystals_dilithium2_PUBLICKEYBYTES),
                sk(pqcrystals_dilithium2_SECRETKEYBYTES) {
        BOOST_REQUIRE_EQUAL(pqcrystals_dilithium2_ref_keypair(pk.data(), sk.data()), 0);
    }
};

static std::vector<uint8_t> AuthSign(const uint256& msg, const std::vector<uint8_t>& sk)
{
    std::vector<uint8_t> sig(pqcrystals_dilithium2_BYTES);
    size_t siglen = 0;
    int ret = pqcrystals_dilithium2_ref_signature(
        sig.data(), &siglen, msg.begin(), 32, nullptr, 0, sk.data());
    BOOST_REQUIRE_EQUAL(ret, 0);
    sig.resize(siglen);
    BOOST_REQUIRE_EQUAL(sig.size(), (size_t)DILITHIUM_SIG_SIZE);
    return sig;
}

static CScript MakeV1Spk(const std::vector<unsigned char>& rawPubkey)
{
    uint256 h; CSHA256().Write(rawPubkey.data(), rawPubkey.size()).Finalize(h.begin());
    CScript s; s << OP_1 << std::vector<unsigned char>(h.begin(), h.end());
    return s;
}

static CScript MakeV8Spk(const std::vector<unsigned char>& rawPubkey)
{
    uint256 h; CSHA256().Write(rawPubkey.data(), rawPubkey.size()).Finalize(h.begin());
    CScript s; s << OP_8 << std::vector<unsigned char>(h.begin(), h.end());
    return s;
}

// Confidential v4 — the "exotic input" a BTCSOQ transfer must refuse.
static CScript MakeV4Spk()
{
    CScript s; s << OP_4 << std::vector<unsigned char>(32, 0x11);
    return s;
}

static std::vector<unsigned char> Prefixed(const std::vector<unsigned char>& rawPubkey)
{
    std::vector<unsigned char> out; out.reserve(rawPubkey.size() + 1);
    out.push_back(0x00);
    out.insert(out.end(), rawPubkey.begin(), rawPubkey.end());
    return out;
}

// OP_RETURN <[tag][payload]> — the signed BTCSOQ op envelope.
static CScript MakeOpEnvelope(uint8_t tag, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> data; data.reserve(1 + payload.size());
    data.push_back(tag);
    data.insert(data.end(), payload.begin(), payload.end());
    CScript s; s << OP_RETURN << data;
    return s;
}

} // namespace

// ---------------------------------------------------------------------------
struct BTCSOQChainSetup : public TestingSetup {
    CKey coinbaseKey;
    CScript coinbaseSpk;
    std::vector<unsigned char> coinbasePk;
    std::vector<CTransaction> coinbaseTxns;

    AuthKey a0, a1, a2;
    std::vector<std::vector<uint8_t>> authKeys;
    CScript markerSpk;

    BTCSOQChainSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        coinbaseKey.MakeNewKey(true);
        CPubKey pk = coinbaseKey.GetPubKey();
        BOOST_REQUIRE(pk.IsValid());
        coinbasePk.assign(pk.begin(), pk.end());
        BOOST_REQUIRE_EQUAL(coinbasePk.size(), 1312u);
        coinbaseSpk = MakeV1Spk(coinbasePk);

        // Authority keyset: 2-of-3. Initialize the global directly (the daemon
        // lazy-inits the same way from chainparams; this bypasses chainparams
        // so the proof is self-contained). Reset the cs_main-protected globals
        // because they persist across BOOST fixtures.
        authKeys = {a0.pk, a1.pk, a2.pk};
        {
            LOCK(cs_main);
            g_btcsoq_supply.Reset();
            g_btcsoq_authority_outpoint.SetNull();
            BOOST_REQUIRE(g_btcsoq_authority.Initialize(authKeys, 2));
        }
        uint256 kh = ComputeAuthorityKeyHash(authKeys);
        markerSpk = CScript() << OP_9 << std::vector<unsigned char>(kh.begin(), kh.end());
        BOOST_REQUIRE_EQUAL(markerSpk.size(), 34u);

        for (int i = 0; i < COINBASE_MATURITY_SOQ; i++) {
            std::vector<CMutableTransaction> none;
            CBlock b = CreateAndProcessBlock(none, coinbaseSpk);
            coinbaseTxns.push_back(*b.vtx[0]);
        }
    }

    ~BTCSOQChainSetup() {
        LOCK(cs_main);
        g_btcsoq_supply.Reset();
        g_btcsoq_authority_outpoint.SetNull();
    }

    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& spk)
    {
        CBlock block = BuildSolvedBlock(txns, spk);
        std::shared_ptr<const CBlock> shared = std::make_shared<const CBlock>(block);
        bool fNewBlock = false;
        ProcessNewBlock(Params(), shared, true, &fNewBlock);
        return block;
    }

    // Solve a block WITHOUT connecting it, so a caller can run TestBlockValidity
    // and read the reject reason. ProcessNewBlock only returns a bool, so a test
    // built on CreateAndProcessBlock can assert that the tip did not move but not
    // WHY — and "the tip did not move" passes for the wrong reject exactly as
    // happily as for the right one. Bead r0vn requires the exact string.
    CBlock BuildSolvedBlock(const std::vector<CMutableTransaction>& txns, const CScript& spk)
    {
        const CChainParams& cp = Params();
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(cp).CreateNewBlock(spk, true);
        BOOST_REQUIRE(tmpl != nullptr);
        CBlock& block = tmpl->block;
        block.vtx.resize(1);
        {
            CMutableTransaction cb(*block.vtx[0]);
            cb.vout.erase(std::remove_if(cb.vout.begin(), cb.vout.end(),
                [](const CTxOut& o) {
                    return o.scriptPubKey.size() >= 38 && o.scriptPubKey[0] == OP_RETURN &&
                           o.scriptPubKey[1] == 0x24 && o.scriptPubKey[2] == 0xaa &&
                           o.scriptPubKey[3] == 0x21 && o.scriptPubKey[4] == 0xa9 &&
                           o.scriptPubKey[5] == 0xed;
                }), cb.vout.end());
            cb.vin[0].scriptWitness.stack.clear();
            block.vtx[0] = MakeTransactionRef(std::move(cb));
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

    // Drive a block through the full ConnectBlock path and return the reject
    // reason, or "" if it validated.
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

    // Drop a mature, spendable coin of an arbitrary witness version straight into
    // the UTXO set. Modifies pcoinsTip directly: an intermediate CCoinsViewCache
    // would flush its unset hashBlock over the tip's and trip ConnectBlock's
    // assertion.
    COutPoint SeedCoin(const CScript& spk, CAmount value, uint8_t tag)
    {
        uint256 txid;
        txid.begin()[0] = tag;
        {
            LOCK(cs_main);
            CCoinsModifier c = pcoinsTip->ModifyCoins(txid);
            c->Clear();
            c->fCoinBase = false;
            c->nHeight   = 1;
            c->nVersion  = 2;
            c->vout.resize(1);
            c->vout[0].nValue       = value;
            c->vout[0].scriptPubKey = spk;
        }
        return COutPoint(txid, 0);
    }

    // Sign a v1 Dilithium input (coinbase / v8 holding) with a CKey.
    void SignV1(CMutableTransaction& tx, unsigned int idx, const CScript& spk,
                CAmount amount, const CKey& key, const std::vector<unsigned char>& rawPk)
    {
        CTransaction ctx(tx);
        uint256 h = SignatureHash(spk, ctx, idx, SIGHASH_ALL, amount, SIGVERSION_WITNESS_V0, nullptr);
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(key.Sign(h, sig));
        sig.push_back((unsigned char)SIGHASH_ALL);
        tx.vin[idx].scriptWitness.stack.clear();
        tx.vin[idx].scriptWitness.stack.push_back(sig);
        tx.vin[idx].scriptWitness.stack.push_back(Prefixed(rawPk));
    }

    // Attach the M-of-N authority witness to the authority input. The sighash is
    // computed over the marker script at that input, amount 0 (mirrors ConnectBlock).
    void SignAuthority(CMutableTransaction& tx, unsigned int authIdx, uint8_t tag)
    {
        CTransaction ctx(tx);
        uint256 h = SignatureHash(markerSpk, ctx, authIdx, SIGHASH_ALL, CAmount(0),
                                  SIGVERSION_WITNESS_V0, nullptr);
        std::vector<uint8_t> s0 = AuthSign(h, a0.sk);
        std::vector<uint8_t> s1 = AuthSign(h, a1.sk);
        std::vector<std::vector<unsigned char>>& w = tx.vin[authIdx].scriptWitness.stack;
        w.clear();
        w.push_back(std::vector<unsigned char>{0x00});        // [0] payout_sig placeholder
        w.push_back(std::vector<unsigned char>{0x00});        // [1] payout_pk placeholder
        w.push_back(std::vector<unsigned char>{tag});         // [2] op tag (== signed OP_RETURN tag)
        w.push_back(std::vector<unsigned char>{0x00});        // [3] payload placeholder
        w.push_back(std::vector<unsigned char>(s0.begin(), s0.end())); // [4] auth sig 0
        w.push_back(std::vector<unsigned char>(s1.begin(), s1.end())); // [5] auth sig 1
        w.push_back(std::vector<unsigned char>{0x00});        // [6] authority_set placeholder
    }

    // MINT MINT_SATS of v8 to `recipient`, bound to (btcTxid, btcVout).
    // Bootstrap (prevMarker == nullptr): the single input is a mature coinbase
    // that carries the authority witness. Chained (prevMarker != nullptr): the
    // authority input spends the tracked marker outpoint, and a coinbase funds
    // the fee — a structurally valid non-bootstrap authority mint.
    CMutableTransaction BuildMint(const CTransaction& fundCoinbase,
                                  const uint256& btcTxid, uint32_t btcVout,
                                  const std::vector<unsigned char>& recipientPk,
                                  const COutPoint* prevMarker = nullptr)
    {
        CMutableTransaction tx; tx.nVersion = 2;
        const CAmount fund = fundCoinbase.vout[0].nValue;

        if (prevMarker) {
            CTxIn mk; mk.prevout = *prevMarker; mk.nSequence = CTxIn::SEQUENCE_FINAL;
            tx.vin.push_back(mk);                                    // vin[0] = authority marker
            CTxIn fee; fee.prevout = COutPoint(fundCoinbase.GetHash(), 0);
            fee.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(fee);  // vin[1] = fee
        } else {
            CTxIn in; in.prevout = COutPoint(fundCoinbase.GetHash(), 0);
            in.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(in);    // vin[0] = coinbase (auth+fund)
        }

        CScript v8spk = MakeV8Spk(recipientPk);
        uint256 commit = ComputeBTCSOQRecipientCommitment(v8spk);
        std::vector<uint8_t> payload = BuildBTCSOQMintPayload(btcTxid, btcVout, MINT_SATS, commit);

        tx.vout.push_back(CTxOut(0, markerSpk));                                  // v9 marker
        tx.vout.push_back(CTxOut(MINT_SATS, v8spk));                             // v8 mint
        tx.vout.push_back(CTxOut(0, MakeOpEnvelope(BTCSOQ_OP_MINT, payload)));   // signed op
        tx.vout.push_back(CTxOut(fund - 10000, coinbaseSpk));                    // SOQ change

        if (prevMarker)
            SignV1(tx, 1, coinbaseSpk, fund, coinbaseKey, coinbasePk);  // fee witness (not verified; HasDilithium)
        SignAuthority(tx, 0, BTCSOQ_OP_MINT);
        return tx;
    }
};

BOOST_FIXTURE_TEST_SUITE(btcsoq_lifecycle_harness_tests, BTCSOQChainSetup)

// ---------------------------------------------------------------------------
// The full happy-path lifecycle in one chain: MINT -> TRANSFER -> BURN.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(mint_transfer_burn_lifecycle)
{
    uint256 depositTxid = uint256S("bccc00000000000000000000000000000000000000000000000000000000d001");

    // ---- MINT ----
    CMutableTransaction mint = BuildMint(coinbaseTxns[0], depositTxid, 0, coinbasePk);
    uint256 mintHash = CTransaction(mint).GetHash();
    CBlock bMint = CreateAndProcessBlock({mint}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == bMint.GetHash(),
        "MINT block must connect");
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.Outstanding(), MINT_SATS);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.TotalMinted(), MINT_SATS);
        BOOST_CHECK(pcoinsdbview->IsBTCSOQMinted(COutPoint(depositTxid, 0)));
        // v8 UTXO exists and is a BTCSOQ holding.
        CCoins c; BOOST_REQUIRE(pcoinsTip->GetCoins(mintHash, c));
        BOOST_CHECK(c.vout[1].IsBTCSOQ());
        BOOST_CHECK_EQUAL(c.vout[1].nValue, MINT_SATS);
    }

    // ---- TRANSFER (non-authority, v8 in == v8 out) ----
    CKey newOwner; newOwner.MakeNewKey(true);
    std::vector<unsigned char> newOwnerPk(newOwner.GetPubKey().begin(), newOwner.GetPubKey().end());
    CMutableTransaction xfer; xfer.nVersion = 2;
    CTxIn v8in; v8in.prevout = COutPoint(mintHash, 1); v8in.nSequence = CTxIn::SEQUENCE_FINAL;
    xfer.vin.push_back(v8in);
    CTxIn feeIn; feeIn.prevout = COutPoint(coinbaseTxns[1].GetHash(), 0);
    feeIn.nSequence = CTxIn::SEQUENCE_FINAL; xfer.vin.push_back(feeIn);
    CScript newV8 = MakeV8Spk(newOwnerPk);
    xfer.vout.push_back(CTxOut(MINT_SATS, newV8));                                   // v8 out == v8 in
    xfer.vout.push_back(CTxOut(coinbaseTxns[1].vout[0].nValue - 10000, coinbaseSpk)); // SOQ change
    SignV1(xfer, 0, MakeV8Spk(coinbasePk), MINT_SATS, coinbaseKey, coinbasePk);       // v8 owner sig
    SignV1(xfer, 1, coinbaseSpk, coinbaseTxns[1].vout[0].nValue, coinbaseKey, coinbasePk); // fee sig
    uint256 xferHash = CTransaction(xfer).GetHash();
    CBlock bXfer = CreateAndProcessBlock({xfer}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == bXfer.GetHash(),
        "TRANSFER block must connect");
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.Outstanding(), MINT_SATS);  // transfers are supply-neutral
        CCoins c; BOOST_REQUIRE(pcoinsTip->GetCoins(xferHash, c));
        BOOST_CHECK(c.vout[0].IsBTCSOQ());
    }

    // ---- BURN (authority tx: spends prev marker + the v8, no v8 out, sats == v8 in) ----
    CMutableTransaction burn; burn.nVersion = 2;
    CTxIn mk; mk.prevout = COutPoint(mintHash, 0); mk.nSequence = CTxIn::SEQUENCE_FINAL; // prev marker
    burn.vin.push_back(mk);
    CTxIn burnV8; burnV8.prevout = COutPoint(xferHash, 0); burnV8.nSequence = CTxIn::SEQUENCE_FINAL;
    burn.vin.push_back(burnV8);
    CTxIn burnFee; burnFee.prevout = COutPoint(coinbaseTxns[2].GetHash(), 0);
    burnFee.nSequence = CTxIn::SEQUENCE_FINAL; burn.vin.push_back(burnFee);
    uint256 releaseHash = uint256S("re1ea5e00000000000000000000000000000000000000000000000000000c0de");
    std::vector<uint8_t> burnPayload = BuildBTCSOQBurnPayload(releaseHash, MINT_SATS);
    burn.vout.push_back(CTxOut(0, markerSpk));                                       // continue chain
    burn.vout.push_back(CTxOut(0, MakeOpEnvelope(BTCSOQ_OP_BURN, burnPayload)));      // signed op
    burn.vout.push_back(CTxOut(coinbaseTxns[2].vout[0].nValue - 10000, coinbaseSpk)); // SOQ change
    // Every input needs a Dilithium witness to pass CheckTransaction's
    // HasDilithiumSignatures (context-free, runs before the authority
    // script-skip in CheckInputs). The authority tx won't script-verify the
    // v8/fee inputs, but the witnesses must be structurally present.
    SignV1(burn, 1, MakeV8Spk(newOwnerPk), MINT_SATS, newOwner, newOwnerPk);          // v8 being burned
    SignV1(burn, 2, coinbaseSpk, coinbaseTxns[2].vout[0].nValue, coinbaseKey, coinbasePk); // fee
    SignAuthority(burn, 0, BTCSOQ_OP_BURN);  // authority witness on the marker-spending input
    CBlock bBurn = CreateAndProcessBlock({burn}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == bBurn.GetHash(),
        "BURN block must connect");
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.TotalBurned(), MINT_SATS);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.Outstanding(), 0);
    }
}

// ---------------------------------------------------------------------------
// Reorg UNDO: disconnecting the mint block reverses the supply and ERASES the
// minted deposit, so the same Bitcoin deposit can back a mint on the new chain.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(reorg_undoes_mint_and_erases_deposit)
{
    uint256 depositTxid = uint256S("bccc00000000000000000000000000000000000000000000000000000000d002");
    CMutableTransaction mint = BuildMint(coinbaseTxns[0], depositTxid, 7, coinbasePk);
    CBlock bMint = CreateAndProcessBlock({mint}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == bMint.GetHash());
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.Outstanding(), MINT_SATS);
        BOOST_CHECK(pcoinsdbview->IsBTCSOQMinted(COutPoint(depositTxid, 7)));
    }

    {
        LOCK(cs_main);
        CValidationState state;
        BlockMap::iterator it = mapBlockIndex.find(bMint.GetHash());
        BOOST_REQUIRE(it != mapBlockIndex.end());
        InvalidateBlock(state, Params(), it->second);
        ActivateBestChain(state, Params());
    }
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() != bMint.GetHash());
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(g_btcsoq_supply.Outstanding() == 0,
            "reorg must UndoMint the supply");
        BOOST_CHECK_MESSAGE(!pcoinsdbview->IsBTCSOQMinted(COutPoint(depositTxid, 7)),
            "reorg must erase the minted deposit so it can re-mint");
    }
}

// ---------------------------------------------------------------------------
// Double-mint REJECTION: a second mint binding the same (btc_txid, vout) is
// consensus-invalid; the block carrying it must not connect.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(double_mint_rejected)
{
    uint256 depositTxid = uint256S("bccc00000000000000000000000000000000000000000000000000000000d003");
    CMutableTransaction mint1 = BuildMint(coinbaseTxns[0], depositTxid, 3, coinbasePk);
    uint256 mint1Hash = CTransaction(mint1).GetHash();
    CBlock b1 = CreateAndProcessBlock({mint1}, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == b1.GetHash());
    uint256 tipAfterFirst = chainActive.Tip()->GetBlockHash();

    // Second mint: a structurally VALID chained authority mint (spends the
    // tracked marker mint1Hash:0, funded by another coinbase, correct sigs and
    // recipient commitment) that binds the SAME deposit. The ONLY reason to
    // reject it is the anti-replay check — so the reject proves anti-replay,
    // not the outpoint-chain rule.
    COutPoint prevMarker(mint1Hash, 0);
    CMutableTransaction mint2 = BuildMint(coinbaseTxns[1], depositTxid, 3, coinbasePk, &prevMarker);
    CBlock b2 = CreateAndProcessBlock({mint2}, coinbaseSpk);
    BOOST_CHECK_MESSAGE(chainActive.Tip()->GetBlockHash() == tipAfterFirst,
        "double-mint block must be rejected — tip unchanged");
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(g_btcsoq_supply.TotalMinted(), MINT_SATS);  // only the first mint counted
    }
}

// ===========================================================================
// REJECT-PATH COVERAGE (beads n1vf, r0vn).
//
// The three rejects below are REACHABLE — unlike the USDSOQ pair, nothing about
// them was dead — and until now none of these strings appeared anywhere under
// src/test/ or qa/. Reachable and unexercised is not a lesser state than dead:
// it is the state a dead rule is indistinguishable from, which is the whole
// point of the r0vn criterion. Each drives a failing input through ConnectBlock
// and asserts the exact string.
// ===========================================================================

// A non-authority tx cannot conjure BTCSOQ. v8 out > v8 in = 0, so the per-asset
// conservation rule must reject it. This is the BTCSOQ mirror of
// usdsoq_v7_conservation_harness_tests::v7_minted_from_soq_is_rejected, and the
// property is load-bearing: without it, any miner could emit a v8 output from
// ordinary SOQ and create Bitcoin-backed supply with no deposit behind it.
BOOST_AUTO_TEST_CASE(connectblock_rejects_btcsoq_minted_from_soq)
{
    const CTransaction& cb = coinbaseTxns[0];
    const CAmount fund = cb.vout[0].nValue;

    CMutableTransaction tx; tx.nVersion = 2;
    CTxIn in; in.prevout = COutPoint(cb.GetHash(), 0); in.nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin.push_back(in);
    tx.vout.push_back(CTxOut(MINT_SATS, MakeV8Spk(coinbasePk)));         // v8 from nothing
    tx.vout.push_back(CTxOut(fund - MINT_SATS - 10000, coinbaseSpk));    // SOQ change
    SignV1(tx, 0, coinbaseSpk, fund, coinbaseKey, coinbasePk);

    BOOST_CHECK_EQUAL(RejectReasonFor({tx}), "bad-txns-btcsoq-not-conserved");
}

// Input-type isolation: a BTCSOQ transfer may spend v8 inputs (the asset) and
// transparent native-SOQ inputs (the fee), nothing else. Here the tx CONSERVES
// v8 exactly, so conservation cannot be what rejects it, and the only thing
// wrong is the v7 USDSOQ input mixed in. Keeping the two assets from meeting in
// one transfer is what stops cross-asset accounting from ever being needed.
BOOST_AUTO_TEST_CASE(connectblock_rejects_exotic_input_in_btcsoq_transfer)
{
    const CAmount v8Val = MINT_SATS;
    COutPoint v8op = SeedCoin(MakeV8Spk(coinbasePk), v8Val, 0xb8);
    // A CONFIDENTIAL v4 input is the exotic one to use here. A v7 USDSOQ input
    // would trip the USDSOQ conservation rule first (v7 in, no v7 out) and the
    // test would pin the wrong string — it did exactly that on the first run.
    // v4 is native SOQ by asset, so it is invisible to both conservation rules,
    // and the only thing it violates is the transparency half of the isolation
    // predicate.
    COutPoint v4op = SeedCoin(MakeV4Spk(), MINT_SATS, 0xb4);

    CMutableTransaction tx; tx.nVersion = 2;
    { CTxIn i0; i0.prevout = v8op; i0.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(i0); }
    { CTxIn i1; i1.prevout = v4op; i1.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(i1); }
    tx.vout.push_back(CTxOut(v8Val, MakeV8Spk(coinbasePk)));   // v8 in == v8 out
    SignV1(tx, 0, MakeV8Spk(coinbasePk), v8Val, coinbaseKey, coinbasePk);
    // The v4 input still needs a witness ending in an ML-DSA pubkey, or
    // CheckTransaction's bad-txns-requires-dilithium fires before we ever reach
    // the isolation rule. The v4 program itself is anyone-can-spend while
    // SoquObscura is dormant, so the signature is not what is being tested.
    SignV1(tx, 1, MakeV4Spk(), MINT_SATS, coinbaseKey, coinbasePk);

    BOOST_CHECK_EQUAL(RejectReasonFor({tx}), "bad-txns-btcsoq-input-mismatch");
}

// Authority operations must be fully transparent: the mint/burn boundary is
// where supply is auditable, and a hidden amount there breaks the invariant
// outright (GENIUS Act 4(a)(2)).
//
// SoquObscura has to be ACTIVE for this to be the rule that fires. While it is
// dormant, SOQ-ARCH-001 rejects every confidential output block-wide, earlier in
// the same ConnectBlock, and would shadow this. That ordering is itself worth
// pinning: the assertion below is what tells us which of the two is doing the
// work at any given time.
BOOST_AUTO_TEST_CASE(connectblock_rejects_confidential_output_in_btcsoq_authority_tx)
{
    ScopedRegtestActivation on(Consensus::DEPLOYMENT_SOQUOBSCURA, 0);

    uint256 depositTxid = uint256S("bccc00000000000000000000000000000000000000000000000000000000dc04");
    CMutableTransaction mint = BuildMint(coinbaseTxns[1], depositTxid, 0, coinbasePk);

    // Add a confidential v4 output funded from the SOQ change, then re-sign:
    // the authority sighash covers the outputs, so an unsigned edit would be
    // caught as a bad signature and prove nothing about the transparency rule.
    CScript v4spk = CScript() << OP_4 << std::vector<unsigned char>(32, 0x11);
    BOOST_REQUIRE_EQUAL(v4spk.size(), 34u);
    CTxOut& change = mint.vout.back();
    BOOST_REQUIRE(change.nValue > MINT_SATS);
    change.nValue -= MINT_SATS;
    mint.vout.push_back(CTxOut(MINT_SATS, v4spk));
    SignAuthority(mint, 0, BTCSOQ_OP_MINT);

    BOOST_CHECK_EQUAL(RejectReasonFor({mint}), "bad-btcsoq-authority-must-be-transparent");
}

// Reachability control for the case above: the SAME mint without the
// confidential output must connect, so the rejection is the transparency rule
// and not an artefact of the edit.
BOOST_AUTO_TEST_CASE(transparent_btcsoq_authority_mint_is_accepted)
{
    ScopedRegtestActivation on(Consensus::DEPLOYMENT_SOQUOBSCURA, 0);

    uint256 depositTxid = uint256S("bccc00000000000000000000000000000000000000000000000000000000dc05");
    CMutableTransaction mint = BuildMint(coinbaseTxns[2], depositTxid, 0, coinbasePk);

    BOOST_CHECK_MESSAGE(RejectReasonFor({mint}).empty(),
        "the identical authority mint without a confidential output must connect");
}

BOOST_AUTO_TEST_SUITE_END()
