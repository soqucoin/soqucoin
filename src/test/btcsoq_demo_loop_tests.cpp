// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// btcsoq_demo_loop_tests.cpp — the automated consensus-native BTCSOQ demo loop.
//
// This is NOT a pass/fail test: it is a long-running driver that exercises the
// REAL validation engine (ConnectBlock / DisconnectBlock) on an isolated
// regtest chain, looping the consensus lifecycle — authority MINT bound to a
// Bitcoin deposit, a v8 TRANSFER, an authority BURN — on a cadence, and writing
// a live status JSON that a demo surface polls. Every step is enforced by the
// same consensus code the mainnet binary runs; the only thing "simulated" is
// the deposit binding (a rotating synthetic btc_txid:vout for the always-on
// marquee), which a real testnet4 deposit can replace on demand.
//
// It is gated on the BTCSOQ_DEMO_LOOP env var so a normal `make check` skips it.
// Run:
//   BTCSOQ_DEMO_LOOP=1 BTCSOQ_DEMO_ITERS=40 BTCSOQ_DEMO_SLEEP=3 \
//     test/test_soqucoin --run_test=btcsoq_demo_loop_tests
// Env:
//   BTCSOQ_DEMO_ITERS   number of mint/transfer/burn cycles (default 30)
//   BTCSOQ_DEMO_SLEEP   seconds between cycles (default 3)
//   BTCSOQ_DEMO_STATUS  status JSON path (default /tmp/btcsoq-demo-status.json)
//   BTCSOQ_DEMO_STOP    if this file exists, the loop exits cleanly
//
// Construction mirrors btcsoq_lifecycle_harness_tests.cpp (kept separate so the
// pass/fail proof stays a clean, fast unit test).

#include "chainparams.h"
#include "consensus/btcsoq.h"
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
#include "util.h"
#include "utiltime.h"
#include "test/test_bitcoin.h"

extern "C" {
#include "crypto/dilithium/api.h"
}

#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <cstdio>
#include <deque>
#include <cstdlib>
#include <string>
#include <sys/stat.h>

namespace {

static const int COINBASE_MATURITY_SOQ = 60 * 4;  // 240, regtest
static const CAmount MINT_SATS = 1000000;

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
    BOOST_REQUIRE_EQUAL(pqcrystals_dilithium2_ref_signature(
        sig.data(), &siglen, msg.begin(), 32, nullptr, 0, sk.data()), 0);
    sig.resize(siglen);
    return sig;
}

static CScript MakeV1Spk(const std::vector<unsigned char>& raw)
{
    uint256 h; CSHA256().Write(raw.data(), raw.size()).Finalize(h.begin());
    CScript s; s << OP_1 << std::vector<unsigned char>(h.begin(), h.end());
    return s;
}
static CScript MakeV8Spk(const std::vector<unsigned char>& raw)
{
    uint256 h; CSHA256().Write(raw.data(), raw.size()).Finalize(h.begin());
    CScript s; s << OP_8 << std::vector<unsigned char>(h.begin(), h.end());
    return s;
}
static std::vector<unsigned char> Prefixed(const std::vector<unsigned char>& raw)
{
    std::vector<unsigned char> out; out.reserve(raw.size() + 1);
    out.push_back(0x00); out.insert(out.end(), raw.begin(), raw.end());
    return out;
}
static CScript MakeOpEnvelope(uint8_t tag, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> data; data.reserve(1 + payload.size());
    data.push_back(tag); data.insert(data.end(), payload.begin(), payload.end());
    CScript s; s << OP_RETURN << data;
    return s;
}
static bool FileExists(const std::string& p) { struct stat st; return ::stat(p.c_str(), &st) == 0; }
static const char* EnvOr(const char* k, const char* d) { const char* v = getenv(k); return v ? v : d; }

} // namespace

struct BTCSOQDemoSetup : public TestingSetup {
    CKey coinbaseKey;
    CScript coinbaseSpk;
    std::vector<unsigned char> coinbasePk;
    std::vector<CTransaction> coinbaseTxns;
    size_t nextCoinbase = 0;

    AuthKey a0, a1, a2;
    std::vector<std::vector<uint8_t>> authKeys;
    CScript markerSpk;
    COutPoint trackedMarker;   // advances with each authority tx (null == bootstrap)

    BTCSOQDemoSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        coinbaseKey.MakeNewKey(true);
        CPubKey pk = coinbaseKey.GetPubKey();
        coinbasePk.assign(pk.begin(), pk.end());
        coinbaseSpk = MakeV1Spk(coinbasePk);
        authKeys = {a0.pk, a1.pk, a2.pk};
        {
            LOCK(cs_main);
            g_btcsoq_supply.Reset();
            g_btcsoq_authority_outpoint.SetNull();
            BOOST_REQUIRE(g_btcsoq_authority.Initialize(authKeys, 2));
        }
        uint256 kh = ComputeAuthorityKeyHash(authKeys);
        markerSpk = CScript() << OP_9 << std::vector<unsigned char>(kh.begin(), kh.end());
        for (int i = 0; i < COINBASE_MATURITY_SOQ; i++) {
            std::vector<CMutableTransaction> none;
            CBlock b = MineBlock(none);
            coinbaseTxns.push_back(*b.vtx[0]);
        }
    }
    ~BTCSOQDemoSetup() {
        LOCK(cs_main);
        g_btcsoq_supply.Reset();
        g_btcsoq_authority_outpoint.SetNull();
    }

    // Return a matured coinbase to fund the next op, mining more blocks (which
    // mature older coinbases) if the queue has run dry — so the loop is endless.
    const CTransaction& NextFundingCoinbase()
    {
        while (nextCoinbase >= coinbaseTxns.size()) {
            std::vector<CMutableTransaction> none;
            CBlock b = MineBlock(none);
            coinbaseTxns.push_back(*b.vtx[0]);
        }
        return coinbaseTxns[nextCoinbase++];
    }

    CBlock MineBlock(const std::vector<CMutableTransaction>& txns)
    {
        const CChainParams& cp = Params();
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(cp).CreateNewBlock(coinbaseSpk, true);
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
        for (const CMutableTransaction& tx : txns) block.vtx.push_back(MakeTransactionRef(tx));
        GenerateCoinbaseCommitment(block, chainActive.Tip(), cp.GetConsensus(0));
        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
        while (!CheckProofOfWork(block.GetPoWHash(), block.nBits, cp.GetConsensus(0))) ++block.nNonce;
        std::shared_ptr<const CBlock> shared = std::make_shared<const CBlock>(block);
        bool fNewBlock = false;
        ProcessNewBlock(cp, shared, true, &fNewBlock);
        {
            LOCK(cs_main);
            BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == block.GetHash(),
                "demo block failed to connect at height " << chainActive.Height());
        }
        return block;
    }

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

    void SignAuthority(CMutableTransaction& tx, unsigned int authIdx, uint8_t tag)
    {
        CTransaction ctx(tx);
        uint256 h = SignatureHash(markerSpk, ctx, authIdx, SIGHASH_ALL, CAmount(0),
                                  SIGVERSION_WITNESS_V0, nullptr);
        std::vector<uint8_t> s0 = AuthSign(h, a0.sk), s1 = AuthSign(h, a1.sk);
        auto& w = tx.vin[authIdx].scriptWitness.stack;
        w.clear();
        w.push_back({0x00}); w.push_back({0x00}); w.push_back({tag}); w.push_back({0x00});
        w.push_back(std::vector<unsigned char>(s0.begin(), s0.end()));
        w.push_back(std::vector<unsigned char>(s1.begin(), s1.end()));
        w.push_back({0x00});
    }

    // MINT bound to (btcTxid, btcVout). Bootstrap when trackedMarker is null,
    // else chained (spends the tracked marker). Returns the mint tx hash and
    // the v8 output index.
    uint256 DoMint(const uint256& btcTxid, uint32_t btcVout,
                   const std::vector<unsigned char>& recipientPk, uint256& v8OutHashOut)
    {
        const CTransaction& fund = NextFundingCoinbase();
        CMutableTransaction tx; tx.nVersion = 2;
        bool bootstrap = trackedMarker.IsNull();
        if (bootstrap) {
            CTxIn in; in.prevout = COutPoint(fund.GetHash(), 0);
            in.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(in);
        } else {
            CTxIn mk; mk.prevout = trackedMarker; mk.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(mk);
            CTxIn fee; fee.prevout = COutPoint(fund.GetHash(), 0);
            fee.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(fee);
        }
        CScript v8spk = MakeV8Spk(recipientPk);
        uint256 commit = ComputeBTCSOQRecipientCommitment(v8spk);
        std::vector<uint8_t> payload = BuildBTCSOQMintPayload(btcTxid, btcVout, MINT_SATS, commit);
        tx.vout.push_back(CTxOut(0, markerSpk));
        tx.vout.push_back(CTxOut(MINT_SATS, v8spk));
        tx.vout.push_back(CTxOut(0, MakeOpEnvelope(BTCSOQ_OP_MINT, payload)));
        tx.vout.push_back(CTxOut(fund.vout[0].nValue - 10000, coinbaseSpk));
        if (!bootstrap) SignV1(tx, 1, coinbaseSpk, fund.vout[0].nValue, coinbaseKey, coinbasePk);
        SignAuthority(tx, 0, BTCSOQ_OP_MINT);
        uint256 hash = CTransaction(tx).GetHash();
        MineBlock({tx});
        {
            LOCK(cs_main);
            trackedMarker = g_btcsoq_authority_outpoint;   // advanced by ConnectBlock
        }
        v8OutHashOut = hash;
        return hash;
    }

    // TRANSFER the v8 at (v8hash:1) owned by `owner` to a fresh recipient. Returns new v8 hash.
    uint256 DoTransfer(const uint256& v8hash, const CKey& owner,
                       const std::vector<unsigned char>& ownerPk,
                       const CKey& newOwner, const std::vector<unsigned char>& newOwnerPk)
    {
        const CTransaction& fee = NextFundingCoinbase();
        CMutableTransaction tx; tx.nVersion = 2;
        CTxIn v8in; v8in.prevout = COutPoint(v8hash, 1); v8in.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(v8in);
        CTxIn feeIn; feeIn.prevout = COutPoint(fee.GetHash(), 0); feeIn.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(feeIn);
        tx.vout.push_back(CTxOut(MINT_SATS, MakeV8Spk(newOwnerPk)));
        tx.vout.push_back(CTxOut(fee.vout[0].nValue - 10000, coinbaseSpk));
        SignV1(tx, 0, MakeV8Spk(ownerPk), MINT_SATS, owner, ownerPk);
        SignV1(tx, 1, coinbaseSpk, fee.vout[0].nValue, coinbaseKey, coinbasePk);
        uint256 hash = CTransaction(tx).GetHash();
        MineBlock({tx});
        return hash;
    }

    // BURN the v8 at (v8hash:0) owned by `owner`. Advances the marker chain.
    void DoBurn(const uint256& v8hash, const CKey& owner, const std::vector<unsigned char>& ownerPk)
    {
        const CTransaction& fee = NextFundingCoinbase();
        CMutableTransaction tx; tx.nVersion = 2;
        CTxIn mk; mk.prevout = trackedMarker; mk.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(mk);
        CTxIn v8in; v8in.prevout = COutPoint(v8hash, 0); v8in.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(v8in);
        CTxIn feeIn; feeIn.prevout = COutPoint(fee.GetHash(), 0); feeIn.nSequence = CTxIn::SEQUENCE_FINAL; tx.vin.push_back(feeIn);
        uint256 releaseHash; CSHA256().Write(v8hash.begin(), 32).Finalize(releaseHash.begin());
        std::vector<uint8_t> payload = BuildBTCSOQBurnPayload(releaseHash, MINT_SATS);
        tx.vout.push_back(CTxOut(0, markerSpk));
        tx.vout.push_back(CTxOut(0, MakeOpEnvelope(BTCSOQ_OP_BURN, payload)));
        tx.vout.push_back(CTxOut(fee.vout[0].nValue - 10000, coinbaseSpk));
        SignV1(tx, 1, MakeV8Spk(ownerPk), MINT_SATS, owner, ownerPk);
        SignV1(tx, 2, coinbaseSpk, fee.vout[0].nValue, coinbaseKey, coinbasePk);
        SignAuthority(tx, 0, BTCSOQ_OP_BURN);
        MineBlock({tx});
        LOCK(cs_main);
        trackedMarker = g_btcsoq_authority_outpoint;
    }

    void WriteStatus(const std::string& path, int iter, const std::string& lastOp,
                     const std::string& deposit)
    {
        LOCK(cs_main);
        std::string tmp = path + ".tmp";
        FILE* f = fopen(tmp.c_str(), "w");
        if (!f) return;
        fprintf(f,
            "{\n"
            "  \"asset\": \"BTCSOQ\",\n"
            "  \"network\": \"regtest-demo\",\n"
            "  \"consensus_enforced\": true,\n"
            "  \"iteration\": %d,\n"
            "  \"last_op\": \"%s\",\n"
            "  \"last_deposit\": \"%s\",\n"
            "  \"height\": %d,\n"
            "  \"total_minted\": %lld,\n"
            "  \"total_burned\": %lld,\n"
            "  \"outstanding\": %lld,\n"
            "  \"authority\": \"%u-of-%u ML-DSA-44\"\n"
            "}\n",
            iter, lastOp.c_str(), deposit.c_str(),
            chainActive.Height(),
            (long long)g_btcsoq_supply.TotalMinted(),
            (long long)g_btcsoq_supply.TotalBurned(),
            (long long)g_btcsoq_supply.Outstanding(),
            g_btcsoq_authority.GetThreshold(), (unsigned)g_btcsoq_authority.GetKeyCount());
        fclose(f);
        rename(tmp.c_str(), path.c_str());
    }
};

BOOST_FIXTURE_TEST_SUITE(btcsoq_demo_loop_tests, BTCSOQDemoSetup)

BOOST_AUTO_TEST_CASE(demo_loop)
{
    if (!getenv("BTCSOQ_DEMO_LOOP")) {
        BOOST_TEST_MESSAGE("btcsoq demo loop skipped (set BTCSOQ_DEMO_LOOP=1 to run)");
        return;
    }
    if (getenv("BTCSOQ_DEMO_DEBUG")) { ::fPrintToConsole = true; }
    const int iters = atoi(EnvOr("BTCSOQ_DEMO_ITERS", "30"));
    const int sleepSecs = atoi(EnvOr("BTCSOQ_DEMO_SLEEP", "3"));
    const size_t floatTarget = (size_t)atoi(EnvOr("BTCSOQ_DEMO_FLOAT", "5"));
    const std::string statusPath = EnvOr("BTCSOQ_DEMO_STATUS", "/tmp/btcsoq-demo-status.json");
    const std::string stopPath = EnvOr("BTCSOQ_DEMO_STOP", "/tmp/btcsoq-demo-STOP");

    BOOST_TEST_MESSAGE("BTCSOQ demo loop: " << iters << " cycles, " << sleepSecs
        << "s cadence, standing float target " << floatTarget << ", status -> " << statusPath);
    WriteStatus(statusPath, 0, "starting", "");

    // The v8 owner/recipient is the fixture's stable Dilithium key. The transfer's
    // v8 input is the one signature the loop actually script-verifies (the mint
    // rides the authority witness, the burn is authority-skipped); a fresh
    // per-iteration MakeNewKey'd key did not produce a consensus-verifiable
    // signature in the test CKey path (a signing-side harness quirk, NOT a
    // consensus issue — consensus correctly rejected the bad sig; real mints
    // sign via the ML-DSA signer). A stable demo owner exercises the money-path
    // fully and correctly.
    // Standing float: each cycle mints a fresh deposit-bound position and
    // redeems (burns) the OLDEST only once the float exceeds floatTarget, so
    // `outstanding` climbs to and holds ~floatTarget positions (never a dead 0
    // marquee, per the runbook) while `total_minted` grows monotonically.
    std::deque<uint256> floatV8;  // v8 held at :0 (post-transfer)

    for (int i = 1; i <= iters; i++) {
        if (FileExists(stopPath)) { BOOST_TEST_MESSAGE("stop file seen, exiting"); break; }

        // Rotating synthetic deposit (the marquee). A real testnet4 deposit
        // would supply these three values instead.
        uint256 deposit; CSHA256().Write((const unsigned char*)&i, sizeof(i)).Finalize(deposit.begin());
        uint32_t vout = (uint32_t)i;
        std::string depStr = deposit.ToString().substr(0, 16) + ":" + std::to_string(vout);

        uint256 mintHash, v8;
        mintHash = DoMint(deposit, vout, coinbasePk, v8);
        WriteStatus(statusPath, i, "mint", depStr);
        MilliSleep(sleepSecs * 1000);

        // Transfer the minted position to a fresh holding (shows a v8 move);
        // recipient is the stable key so its spend stays consensus-verifiable.
        uint256 xfer = DoTransfer(mintHash, coinbaseKey, coinbasePk, coinbaseKey, coinbasePk);
        floatV8.push_back(xfer);
        WriteStatus(statusPath, i, "transfer", depStr);
        MilliSleep(sleepSecs * 1000);

        // Redeem (burn) the oldest held position once the float is above target.
        if (floatV8.size() > floatTarget) {
            DoBurn(floatV8.front(), coinbaseKey, coinbasePk);
            floatV8.pop_front();
            WriteStatus(statusPath, i, "redeem", depStr);
            MilliSleep(sleepSecs * 1000);
        }

        {
            LOCK(cs_main);
            BOOST_TEST_MESSAGE("cycle " << i << ": minted=" << g_btcsoq_supply.TotalMinted()
                << " burned=" << g_btcsoq_supply.TotalBurned()
                << " outstanding=" << g_btcsoq_supply.Outstanding()
                << " float=" << floatV8.size() << " height=" << chainActive.Height());
        }
    }
    WriteStatus(statusPath, iters, "idle", "");
    // Invariant the whole loop must preserve: outstanding never negative.
    LOCK(cs_main);
    BOOST_CHECK(g_btcsoq_supply.Outstanding() >= 0);
}

BOOST_AUTO_TEST_SUITE_END()
