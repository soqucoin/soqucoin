// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// keyhash_broadcast_tests.cpp
// ---------------------------------------------------------------------------
// Phase 1a on-chain broadcast integration test (SOQ-COV-013).
//
// WHAT THIS PROVES (from PHASE1A_BROADCAST_CHECKLIST.md):
//   1) The node accepts+mines a tx spending a keyhash-2-of-2 v6 output with a
//      real 2-of-2 Dilithium witness.
//   2) APO 0x42 rebinding works on-chain for the update tx.
//   3) BIP68 relative timelock (CSV 288) gates the settlement spend of the
//      update output: REJECT pre-288, ACCEPT post-288.
//
// WHAT THIS DOES NOT PROVE (explicit scope boundary):
//   The eLTOO supersession guard (a newer-state update spending an older update
//   output). The update output U:0 is a plain keyhash-2-of-2, not a
//   state-guarded output.
//
// APPROACH:
//   Uses TestingSetup (regtest) with manually mined blocks. Coinbase outputs
//   are v6 P2WSH-Dilithium single-key scripts, spendable with a proper v6
//   witness that passes HasDilithiumSignatures().
//
//   Transaction graph:
//     F (funding)   → coinbase spend → keyhash-2-of-2 output (value V)
//     U (update)    → spends F:0 with APO 0x42 → keyhash-2-of-2 (value V-fee)
//     S (settlement)→ spends U:0 with CSV 288  → OP_TRUE payout (value V-2*fee)
//
// BUILD + RUN:
//   make -j$(sysctl -n hw.ncpu) test/test_soqucoin
//   test/test_soqucoin --run_test=keyhash_broadcast_tests --log_level=message

#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "key.h"
#include "miner.h"

#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "test/test_bitcoin.h"
#include "txmempool.h"
#include "utilstrencodings.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

// ============================================================================
// Helpers (shared with dilithium_keyhash_committed_tests.cpp patterns)
// ============================================================================

namespace {

// V1 Dilithium single-key scriptPubKey: OP_1 <SHA256(rawPubkey)>  (34 bytes).
// Used for coinbase outputs (required by CreateNewBlock's dilithiumOnlyHeight check).
static CScript MakeV1Spk(const std::vector<unsigned char>& rawPubkey)
{
    uint256 pkHash;
    CSHA256().Write(rawPubkey.data(), rawPubkey.size()).Finalize(pkHash.begin());
    CScript spk;
    spk << OP_1;
    spk << std::vector<unsigned char>(pkHash.begin(), pkHash.end());
    return spk;
}

// V6 P2WSH-Dilithium scriptPubKey: OP_6 <SHA256(witnessScript)>  (34 bytes).
// Used for 2-of-2 keyhash outputs (covenant script execution).
static CScript MakeV6Spk(const CScript& witnessScript)
{
    uint256 scriptHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(scriptHash.begin());
    CScript spk;
    spk << OP_6;
    spk << std::vector<unsigned char>(scriptHash.begin(), scriptHash.end());
    return spk;
}

// SHA256(rawPubkey) — the keyhash committed in the witnessScript.
static std::vector<unsigned char> KeyHash(const std::vector<unsigned char>& rawPubkey)
{
    BOOST_REQUIRE_EQUAL(rawPubkey.size(), 1312u);
    unsigned char h[32];
    CSHA256().Write(rawPubkey.data(), rawPubkey.size()).Finalize(h);
    return std::vector<unsigned char>(h, h + 32);
}

// 0x00-prefixed (FIPS 204) pubkey for the trailing v6 witness item.
static std::vector<unsigned char> Prefixed(const std::vector<unsigned char>& rawPubkey)
{
    std::vector<unsigned char> out;
    out.reserve(rawPubkey.size() + 1);
    out.push_back(0x00);
    out.insert(out.end(), rawPubkey.begin(), rawPubkey.end());
    return out;
}

// Sign a sighash and append the hashtype byte.
// Returns raw 2420-byte ML-DSA-44 sig + 1-byte hashtype = 2421 bytes.
static std::vector<unsigned char> SignWith(const CKey& key,
                                           const CScript& scriptCode,
                                           const CTransaction& tx,
                                           unsigned int nIn,
                                           const CAmount& amount,
                                           int hashType)
{
    uint256 sighash = SignatureHash(scriptCode, tx, nIn, hashType, amount,
                                    SIGVERSION_WITNESS_V0, nullptr);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    BOOST_REQUIRE_EQUAL(sig.size(), 2420u);
    sig.push_back(static_cast<unsigned char>(hashType));
    return sig;
}

// AcceptToMemoryPool wrapper that captures the rejection reason.
static bool ToMemPool(CMutableTransaction& tx, std::string& rejectReason)
{
    LOCK(cs_main);
    CValidationState state;
    bool ok = AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx),
                                 false, nullptr, nullptr, true, 0);
    if (!ok) {
        rejectReason = FormatStateMessage(state);
    }
    return ok;
}

// Overload without reject-reason capture.
static bool ToMemPool(CMutableTransaction& tx)
{
    std::string reason;
    return ToMemPool(tx, reason);
}

// Coinbase maturity for Soqucoin regtest: 60 * 4 = 240 blocks.
static const int COINBASE_MATURITY_SOQ = 60 * 4;

} // namespace

// ============================================================================
// Fixture: builds a 240-block regtest chain with v1 Dilithium coinbase outputs.
// v1 (OP_1 <SHA256(pk)>) is required because CreateNewBlock enforces
// dilithiumOnlyHeight=0 on regtest (miner.cpp:201). The 2-of-2 keyhash
// outputs in the test use v6 P2WSH-Dilithium for covenant execution.
// ============================================================================
struct DilithiumCoinbaseChainSetup : public TestingSetup {
    CKey coinbaseKey;
    CScript coinbaseSpk;             // OP_1 <SHA256(rawPk)>
    std::vector<unsigned char> coinbasePkBytes;
    std::vector<CTransaction> coinbaseTxns;

    DilithiumCoinbaseChainSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        coinbaseKey.MakeNewKey(true);
        CPubKey pk = coinbaseKey.GetPubKey();
        BOOST_REQUIRE(pk.IsValid());
        coinbasePkBytes.assign(pk.begin(), pk.end());
        BOOST_REQUIRE_EQUAL(coinbasePkBytes.size(), 1312u);

        // Witness v1 single-key Dilithium: OP_1 <SHA256(rawPubkey)>
        coinbaseSpk = MakeV1Spk(coinbasePkBytes);
        BOOST_REQUIRE_EQUAL(coinbaseSpk.size(), 34u);
        BOOST_REQUIRE_EQUAL(coinbaseSpk[0], OP_1);   // v1 required by miner
        BOOST_REQUIRE_EQUAL(coinbaseSpk[1], 32);      // 32-byte program

        // Mine 240 blocks (coinbase maturity)
        for (int i = 0; i < COINBASE_MATURITY_SOQ; i++) {
            std::vector<CMutableTransaction> noTxns;
            CBlock b = CreateAndProcessBlock(noTxns, coinbaseSpk);
            coinbaseTxns.push_back(*b.vtx[0]);
        }
    }

    // Mine a block with specific txns (drops mempool txns, adds passed-in txns).
    // Used during fixture setup to mine empty blocks.
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns,
                                 const CScript& scriptPubKey)
    {
        const CChainParams& chainparams = Params();
        std::unique_ptr<CBlockTemplate> pblocktemplate =
            BlockAssembler(chainparams).CreateNewBlock(scriptPubKey, true);
        BOOST_REQUIRE(pblocktemplate != nullptr);
        CBlock& block = pblocktemplate->block;

        // Replace mempool-selected txns with just coinbase + passed-in txns
        block.vtx.resize(1);
        for (const CMutableTransaction& tx : txns)
            block.vtx.push_back(MakeTransactionRef(tx));

        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

        while (!CheckProofOfWork(block.GetPoWHash(), block.nBits,
                                  chainparams.GetConsensus(0)))
            ++block.nNonce;

        std::shared_ptr<const CBlock> shared_pblock =
            std::make_shared<const CBlock>(block);
        ProcessNewBlock(chainparams, shared_pblock, true, nullptr);

        return block;
    }

    // Mine a block that includes whatever is currently in the mempool.
    // Used during the test to mine F, U, S after they've been submitted.
    CBlock MineBlock()
    {
        const CChainParams& chainparams = Params();
        std::unique_ptr<CBlockTemplate> pblocktemplate =
            BlockAssembler(chainparams).CreateNewBlock(coinbaseSpk, true);
        BOOST_REQUIRE(pblocktemplate != nullptr);
        CBlock& block = pblocktemplate->block;

        // DON'T strip mempool txns — let the assembler include them.

        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

        while (!CheckProofOfWork(block.GetPoWHash(), block.nBits,
                                  chainparams.GetConsensus(0)))
            ++block.nNonce;

        std::shared_ptr<const CBlock> shared_pblock =
            std::make_shared<const CBlock>(block);
        ProcessNewBlock(chainparams, shared_pblock, true, nullptr);

        return block;
    }

    // Build a tx spending a v1 single-key coinbase output (for funding tx F).
    // Returns a SIGNED CMutableTransaction with proper v1 Dilithium witness.
    // Witness v1 stack: [sig+hashtype, 0x00||pubkey]  (2 items)
    CMutableTransaction SpendCoinbase(int coinbaseIdx,
                                      const CScript& outputSpk,
                                      CAmount outputValue)
    {
        const CTransaction& cbTx = coinbaseTxns[coinbaseIdx];
        CAmount cbValue = cbTx.vout[0].nValue;
        BOOST_REQUIRE(outputValue <= cbValue);

        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.nLockTime = 0;

        CTxIn in;
        in.prevout.hash = cbTx.GetHash();
        in.prevout.n = 0;
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        mtx.vin.push_back(in);

        CTxOut out;
        out.nValue = outputValue;
        out.scriptPubKey = outputSpk;
        out.nVisibility = 0;
        out.nAssetType = 0;
        mtx.vout.push_back(out);

        // Sign the coinbase spend (single-key v1 Dilithium).
        // For v1, the scriptCode passed to SignatureHash is the scriptPubKey
        // itself (OP_1 <32-byte hash>), matching sign.cpp.
        CTransaction ctx(mtx);
        std::vector<unsigned char> sig =
            SignWith(coinbaseKey, coinbaseSpk, ctx, 0, cbValue,
                     SIGHASH_ALL);

        // Witness v1 stack: [sig+hashtype, 0x00-prefixed pubkey]
        CScriptWitness w;
        w.stack.push_back(sig);                    // [0]: sig (2420) + hashtype (1) = 2421 bytes
        w.stack.push_back(Prefixed(coinbasePkBytes)); // [1]: 0x00||rawPk = 1313 bytes

        mtx.vin[0].scriptWitness = w;
        return mtx;
    }

    ~DilithiumCoinbaseChainSetup() {}
};

// ============================================================================
// THE TEST: keyhash-2-of-2 eLTOO graph on regtest
//   F (funding) → U (update, APO 0x42) → S (settlement, CSV 288)
//   Proves: mempool acceptance, BIP68 rejection pre-288, acceptance post-288.
// ============================================================================
BOOST_FIXTURE_TEST_SUITE(keyhash_broadcast_tests, DilithiumCoinbaseChainSetup)

BOOST_AUTO_TEST_CASE(keyhash_2of2_eltoo_graph_regtest)
{
    // ----------------------------------------------------------------
    // Step 0: Generate two Dilithium keypairs (A and B)
    // ----------------------------------------------------------------
    CKey alice, bob;
    alice.MakeNewKey(true);
    bob.MakeNewKey(true);
    CPubKey alicePk = alice.GetPubKey(), bobPk = bob.GetPubKey();
    BOOST_REQUIRE(alicePk.IsValid() && bobPk.IsValid());
    std::vector<unsigned char> aPk(alicePk.begin(), alicePk.end());
    std::vector<unsigned char> bPk(bobPk.begin(), bobPk.end());
    BOOST_REQUIRE_EQUAL(aPk.size(), 1312u);
    BOOST_REQUIRE_EQUAL(bPk.size(), 1312u);

    BOOST_TEST_MESSAGE("=== Phase 1a: keyhash-2-of-2 eLTOO graph on regtest ===");
    BOOST_TEST_MESSAGE("Alice pubkey SHA256: " << HexStr(KeyHash(aPk)));
    BOOST_TEST_MESSAGE("Bob   pubkey SHA256: " << HexStr(KeyHash(bPk)));

    // ----------------------------------------------------------------
    // Step 1: Construct the 2-of-2 witnessScript and scriptPubKey
    // ----------------------------------------------------------------
    // witnessScript: <khB> OP_CDKH <khA> OP_CDKH OP_1   (69 bytes)
    // B is committed first because the first opcode checks the TOP eval item,
    // and the witness puts pubB on top.
    CScript ws;
    ws << KeyHash(bPk)  << OP_CHECKDILITHIUMKEYHASH
       << KeyHash(aPk)  << OP_CHECKDILITHIUMKEYHASH
       << OP_1;
    CScript spk = MakeV6Spk(ws);
    BOOST_REQUIRE_EQUAL(ws.size(), 69u);
    BOOST_REQUIRE_EQUAL(spk.size(), 34u);
    BOOST_TEST_MESSAGE("2-of-2 witnessScript: " << HexStr(ws));
    BOOST_TEST_MESSAGE("2-of-2 scriptPubKey:  " << HexStr(spk));

    // ----------------------------------------------------------------
    // Step 2: Fee calculation
    // ----------------------------------------------------------------
    // 2-of-2 Dilithium witness ≈ 8.85 KB:
    //   2 × (2421 sig + 1312 pubkey) + 69 ws + 1313 trailing ≈ 8848 bytes
    // With witness discount (÷4), vsize ≈ 2212 + base overhead ≈ ~2300 vB.
    // Use 50000 sat fee (generous — well above 1 sat/vB × 2300 vB).
    const CAmount FEE = 50000;

    // Coinbase value at block 1 on regtest (fSimplifiedRewards, halving=150):
    // Block 0..149 → (500000 * COIN) >> 0 = 500,000 COIN (regtest fixture; nInitialSubsidy=500000).
    CAmount cbValue = coinbaseTxns[0].vout[0].nValue;
    BOOST_TEST_MESSAGE("Coinbase[0] value: " << cbValue << " sat ("
                       << (cbValue / COIN) << " SOQ)");
    BOOST_REQUIRE(cbValue > 3 * FEE);  // sanity

    const CAmount V = cbValue - FEE;          // F output value (funding capacity)
    const CAmount V_U = V - FEE;              // U output value
    const CAmount V_S = V_U - FEE;            // S output value (total payout)

    // ----------------------------------------------------------------
    // Step 3: Build F (funding tx) — spends coinbase[0] → 2-of-2 output
    // ----------------------------------------------------------------
    CMutableTransaction fundTx = SpendCoinbase(0, spk, V);
    BOOST_TEST_MESSAGE("F txid: " << CTransaction(fundTx).GetHash().ToString());

    // ----------------------------------------------------------------
    // Step 4: Build U (update tx) — spends F:0 with APO 0x42
    // ----------------------------------------------------------------
    // U output is the SAME 2-of-2 keyhash script (re-closable).
    CMutableTransaction updateTx;
    updateTx.nVersion = 2;
    updateTx.nLockTime = 0;
    {
        CTxIn in;
        in.prevout.hash = CTransaction(fundTx).GetHash();
        in.prevout.n = 0;
        in.nSequence = 0xffffffff;  // final (no CSV on U's input)
        updateTx.vin.push_back(in);
    }
    {
        CTxOut out;
        out.nValue = V_U;
        out.scriptPubKey = spk;  // same 2-of-2
        out.nVisibility = 0;
        out.nAssetType = 0;
        updateTx.vout.push_back(out);
    }

    // Sign U with APO 0x42 — both parties sign the SAME sighash.
    // SIGHASH_ANYPREVOUTANYSCRIPT: prevout, sequence, scriptCode NOT committed;
    // amount IS committed. Rebindable to any funding output of the same value.
    {
        CTransaction ctx(updateTx);
        const int apo = SIGHASH_ANYPREVOUTANYSCRIPT;  // 0x42
        std::vector<unsigned char> sigA = SignWith(alice, ws, ctx, 0, V, apo);
        std::vector<unsigned char> sigB = SignWith(bob,   ws, ctx, 0, V, apo);

        CScriptWitness w;
        w.stack.push_back(sigA);          // eval[0]: sigA
        w.stack.push_back(aPk);           // eval[1]: pubkeyA
        w.stack.push_back(sigB);          // eval[2]: sigB
        w.stack.push_back(bPk);           // eval[3]: pubkeyB (top → checked first)
        w.stack.push_back(std::vector<unsigned char>(ws.begin(), ws.end()));
        w.stack.push_back(Prefixed(aPk)); // trailing 0x00||pk
        updateTx.vin[0].scriptWitness = w;
    }
    BOOST_TEST_MESSAGE("U txid: " << CTransaction(updateTx).GetHash().ToString());

    // ----------------------------------------------------------------
    // Step 5: Build S (settlement tx) — spends U:0 with CSV 288, SIGHASH_ALL
    // ----------------------------------------------------------------
    CMutableTransaction settleTx;
    settleTx.nVersion = 2;
    settleTx.nLockTime = 0;
    {
        CTxIn in;
        in.prevout.hash = CTransaction(updateTx).GetHash();
        in.prevout.n = 0;
        in.nSequence = 288;  // BIP68: 288 blocks relative lock
        settleTx.vin.push_back(in);
    }
    {
        // Payout to OP_TRUE (simplest valid output for testing).
        // Split: Alice gets 60%, Bob 40%.
        CAmount alicePayout = (V_S * 6) / 10;
        CAmount bobPayout   = V_S - alicePayout;

        // Alice payout — use a v6 single-key script so it's standard
        CScript alicePayoutWs;
        alicePayoutWs << KeyHash(aPk) << OP_CHECKDILITHIUMKEYHASH << OP_1;
        CTxOut outA;
        outA.nValue = alicePayout;
        outA.scriptPubKey = MakeV6Spk(alicePayoutWs);
        outA.nVisibility = 0;
        outA.nAssetType = 0;
        settleTx.vout.push_back(outA);

        // Bob payout
        CScript bobPayoutWs;
        bobPayoutWs << KeyHash(bPk) << OP_CHECKDILITHIUMKEYHASH << OP_1;
        CTxOut outB;
        outB.nValue = bobPayout;
        outB.scriptPubKey = MakeV6Spk(bobPayoutWs);
        outB.nVisibility = 0;
        outB.nAssetType = 0;
        settleTx.vout.push_back(outB);
    }

    // Sign S with SIGHASH_ALL 0x01 — commits prevout + nSequence + outputs.
    {
        CTransaction ctx(settleTx);
        std::vector<unsigned char> sigA = SignWith(alice, ws, ctx, 0, V_U, SIGHASH_ALL);
        std::vector<unsigned char> sigB = SignWith(bob,   ws, ctx, 0, V_U, SIGHASH_ALL);

        CScriptWitness w;
        w.stack.push_back(sigA);
        w.stack.push_back(aPk);
        w.stack.push_back(sigB);
        w.stack.push_back(bPk);
        w.stack.push_back(std::vector<unsigned char>(ws.begin(), ws.end()));
        w.stack.push_back(Prefixed(aPk));
        settleTx.vin[0].scriptWitness = w;
    }
    BOOST_TEST_MESSAGE("S txid: " << CTransaction(settleTx).GetHash().ToString());

    // ================================================================
    // PRE-FLIGHT COMPLETE: All txs (F, U, S) are built and signed in memory.
    // Now broadcast in sequence per checklist §5.
    // ================================================================

    BOOST_TEST_MESSAGE("\n=== Broadcasting F (funding) ===");

    // ----------------------------------------------------------------
    // Step 6: Broadcast F → mine 1 block
    // ----------------------------------------------------------------
    {
        std::string reason;
        bool ok = ToMemPool(fundTx, reason);
        BOOST_CHECK_MESSAGE(ok,
            "F must be accepted to mempool; reject=" << reason);
        if (!ok) {
            BOOST_TEST_MESSAGE("FINDING: F rejected: " << reason);
            BOOST_TEST_MESSAGE("F size: " << std::to_string(
                ::GetSerializeSize(CTransaction(fundTx), SER_NETWORK, PROTOCOL_VERSION)) << " bytes");
            // Don't proceed if F is rejected — the graph is broken.
            BOOST_FAIL("Cannot continue: F rejected from mempool.");
        }
    }
    // Mine a block containing F.
    {
        CBlock b = MineBlock();
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == b.GetHash());
        BOOST_TEST_MESSAGE("F mined in block " << chainActive.Height());
    }
    // Confirm F is no longer in mempool (mined).
    BOOST_CHECK_EQUAL(mempool.size(), 0u);

    // ----------------------------------------------------------------
    // Step 7: Broadcast U (update, APO 0x42) → mine 1 block
    // ----------------------------------------------------------------
    BOOST_TEST_MESSAGE("\n=== Broadcasting U (update, APO 0x42) ===");
    {
        std::string reason;
        bool ok = ToMemPool(updateTx, reason);
        BOOST_CHECK_MESSAGE(ok,
            "U must be accepted to mempool (keyhash-2-of-2 + APO 0x42); reject=" << reason);
        if (!ok) {
            BOOST_TEST_MESSAGE("FINDING: U rejected: " << reason);
            BOOST_FAIL("Cannot continue: U rejected from mempool.");
        }
    }
    // Mine a block containing U.
    {
        CBlock b = MineBlock();
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == b.GetHash());
        BOOST_TEST_MESSAGE("U mined in block " << chainActive.Height()
                           << " — keyhash-2-of-2 funding spend + APO 0x42 PROVEN ON-CHAIN");
    }
    BOOST_CHECK_EQUAL(mempool.size(), 0u);

    int uConfHeight = chainActive.Height();  // U's confirmation height

    // ----------------------------------------------------------------
    // Step 8: S early → EXPECT REJECT (non-BIP68-final)
    // ----------------------------------------------------------------
    BOOST_TEST_MESSAGE("\n=== Broadcasting S EARLY (expect BIP68 rejection) ===");
    BOOST_TEST_MESSAGE("U confirmed at height " << uConfHeight
                       << ", current tip = " << chainActive.Height()
                       << " → only 1 conf (need 288)");
    {
        std::string reason;
        bool ok = ToMemPool(settleTx, reason);
        BOOST_CHECK_MESSAGE(!ok,
            "S MUST be rejected pre-288 confs; but was ACCEPTED (this is a bug!)");
        // The exact reject reason should contain "non-BIP68-final".
        BOOST_CHECK_MESSAGE(reason.find("non-BIP68-final") != std::string::npos,
            "S rejection must be 'non-BIP68-final'; got: " << reason);
        BOOST_TEST_MESSAGE("S correctly REJECTED pre-288: " << reason
                           << " ← CSV timelock proven");
    }

    // ----------------------------------------------------------------
    // Step 9: Mine 287 more blocks (total 288 confs on U)
    // ----------------------------------------------------------------
    BOOST_TEST_MESSAGE("\n=== Mining 287 more blocks (total 288 confs on U) ===");
    for (int i = 0; i < 287; i++) {
        std::vector<CMutableTransaction> noTxns;
        CreateAndProcessBlock(noTxns, coinbaseSpk);
    }
    int totalConfs = chainActive.Height() - uConfHeight;
    BOOST_TEST_MESSAGE("U now has " << totalConfs << " confirmations"
                       << " (tip=" << chainActive.Height() << ")");
    // BIP68 requires >= 288 confs. After mining 287 more blocks on top of the
    // block that included U, U has 288 confs (including the block it's in).
    // Actually: confs = tip_height - confirm_height + 1 in user terms,
    // but BIP68's CalculateSequenceLocks uses raw block heights.
    // With 1 block mined after U + 287 more = tip at uConfHeight + 288.
    // CheckSequenceLocks evaluates at tip+1, so the lock height is
    // uConfHeight + 288, and tip+1 = uConfHeight + 289. Should pass.

    // ----------------------------------------------------------------
    // Step 10: S again → EXPECT ACCEPT (CSV 288 satisfied)
    // ----------------------------------------------------------------
    BOOST_TEST_MESSAGE("\n=== Broadcasting S post-288 (expect ACCEPT) ===");
    {
        std::string reason;
        bool ok = ToMemPool(settleTx, reason);
        BOOST_CHECK_MESSAGE(ok,
            "S must be accepted post-288 confs (BIP68 CSV proven); reject=" << reason);
        if (!ok) {
            BOOST_TEST_MESSAGE("FINDING: S still rejected post-288: " << reason);
        }
    }
    // Mine a final block containing S.
    {
        CBlock b = MineBlock();
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == b.GetHash());
        BOOST_TEST_MESSAGE("S mined in block " << chainActive.Height()
                           << " — BIP68 CSV 288 PROVEN ON-CHAIN");
    }
    BOOST_CHECK_EQUAL(mempool.size(), 0u);

    // ================================================================
    // SUMMARY
    // ================================================================
    BOOST_TEST_MESSAGE("\n"
        "=== Phase 1a REGTEST RESULTS ===\n"
        "F (funding)    : ACCEPTED + MINED — coinbase → keyhash-2-of-2 v6\n"
        "U (update)     : ACCEPTED + MINED — keyhash-2-of-2 spend + APO 0x42\n"
        "S (early)      : REJECTED non-BIP68-final (1 conf < 288) ← CSV PROVEN\n"
        "S (post-288)   : ACCEPTED + MINED — CSV 288 satisfied\n"
        "=== Phase 1a on regtest: GREEN ===");
}

BOOST_AUTO_TEST_SUITE_END()
