// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// freeze_registry_harness_tests.cpp — REAL consensus-path test for the freeze
// registry (CTxOut migration Phase 1). Unlike freeze_registry_tests.cpp (which
// exercises the storage layer + parser in isolation), THIS drives actual
// ConnectBlock / DisconnectBlock through the validation engine, so it tests the
// R1 security guards in situ — the thing that was missing (review R4) and the
// only way to actually prove R1 is fixed and stays fixed.
//
// Primary test: R1 regression. ConnectBlock APPLY only acts on authority TXs
// (OP_5 output); DisconnectBlock REVERSE must mirror that guard. Without it, a
// NON-authority tx carrying a forged `OP_RETURN "FREEZE"[op=FREEZE][X]` — ignored
// at connect — would be INVERTED at disconnect, erasing a legitimate freeze on X
// (freeze bypass) or phantom-freezing a victim. This test mines such a tx in a
// block, reorgs it out, and asserts a seeded freeze survives.
//
// ⚠️ Fable wrote this against the keyhash_broadcast_tests harness pattern but could
// NOT compile it (fresh worktree). Buddy: build-fix any harness/API mismatches,
// then register in src/Makefile.test.include. NOTE: the R1 reverse guard also has a
// height gate (>= nUSDSOQAuthorityEnforcementHeight); this test only isolates the
// OP_5 guard if the test height is at/above regtest's enforcement height (expected 0,
// like mainnet — confirm regtest's value).

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

static std::vector<unsigned char> Prefixed(const std::vector<unsigned char>& rawPubkey)
{
    std::vector<unsigned char> out;
    out.push_back(0x00);
    out.insert(out.end(), rawPubkey.begin(), rawPubkey.end());
    return out;
}

// Sign a sighash, append the hashtype byte (2420 + 1 = 2421).
static std::vector<unsigned char> SignWith(const CKey& key, const CScript& scriptCode,
    const CTransaction& tx, unsigned int nIn, const CAmount& amount, int hashType)
{
    uint256 sighash = SignatureHash(scriptCode, tx, nIn, hashType, amount, SIGVERSION_WITNESS_V0, nullptr);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    BOOST_REQUIRE_EQUAL(sig.size(), 2420u);
    sig.push_back((unsigned char)hashType);
    return sig;
}

// Build a well-formed freeze OP_RETURN: OP_RETURN <"FREEZE"> <[op][txid][vout LE]>.
static CScript MakeFreezeOpReturn(uint8_t op, const uint256& txid, uint32_t vout)
{
    std::vector<uint8_t> tag = {'F','R','E','E','Z','E'};
    std::vector<uint8_t> payload(FREEZE_OP_PAYLOAD_LEN);
    payload[0] = op;
    memcpy(&payload[1], txid.begin(), 32);
    payload[33] = vout & 0xFF; payload[34] = (vout >> 8) & 0xFF;
    payload[35] = (vout >> 16) & 0xFF; payload[36] = (vout >> 24) & 0xFF;
    CScript s; s << OP_RETURN << tag << payload;
    return s;
}

} // namespace

// 240-block regtest chain with v1 Dilithium coinbases (matches keyhash_broadcast_tests).
struct FreezeChainSetup : public TestingSetup {
    CKey coinbaseKey;
    CScript coinbaseSpk;
    std::vector<unsigned char> coinbasePkBytes;
    std::vector<CTransaction> coinbaseTxns;

    FreezeChainSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        coinbaseKey.MakeNewKey(true);
        CPubKey pk = coinbaseKey.GetPubKey();
        BOOST_REQUIRE(pk.IsValid());
        coinbasePkBytes.assign(pk.begin(), pk.end());
        coinbaseSpk = MakeV1Spk(coinbasePkBytes);
        for (int i = 0; i < COINBASE_MATURITY_SOQ; i++) {
            std::vector<CMutableTransaction> noTxns;
            CBlock b = CreateAndProcessBlock(noTxns, coinbaseSpk);
            coinbaseTxns.push_back(*b.vtx[0]);
        }
    }

    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& spk)
    {
        const CChainParams& cp = Params();
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(cp).CreateNewBlock(spk, true);
        BOOST_REQUIRE(tmpl != nullptr);
        CBlock& block = tmpl->block;
        block.vtx.resize(1);
        for (const CMutableTransaction& tx : txns) block.vtx.push_back(MakeTransactionRef(tx));
        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
        while (!CheckProofOfWork(block.GetPoWHash(), block.nBits, cp.GetConsensus(0))) ++block.nNonce;
        std::shared_ptr<const CBlock> shared = std::make_shared<const CBlock>(block);
        ProcessNewBlock(cp, shared, true, nullptr);
        return block;
    }

    // A NON-authority tx (no OP_5 output) that validly spends a mature coinbase and
    // carries a forged FREEZE op naming `target`.
    CMutableTransaction BuildForgedFreezeTx(const CTransaction& coinbase, uint8_t op, const COutPoint& target)
    {
        CMutableTransaction tx;
        tx.nVersion = 2;
        const CAmount inVal = coinbase.vout[0].nValue;
        CTxIn in; in.prevout = COutPoint(coinbase.GetHash(), 0); in.nSequence = CTxIn::SEQUENCE_FINAL;
        tx.vin.push_back(in);
        CTxOut payout; payout.nValue = inVal - 10000; payout.scriptPubKey = coinbaseSpk; // v1, NOT OP_5
        tx.vout.push_back(payout);
        CTxOut opret; opret.nValue = 0; opret.scriptPubKey = MakeFreezeOpReturn(op, target.hash, target.n);
        tx.vout.push_back(opret);
        std::vector<unsigned char> sig = SignWith(coinbaseKey, coinbaseSpk, CTransaction(tx), 0, inVal, SIGHASH_ALL);
        tx.vin[0].scriptWitness.stack.clear();
        tx.vin[0].scriptWitness.stack.push_back(sig);
        tx.vin[0].scriptWitness.stack.push_back(Prefixed(coinbasePkBytes));
        return tx;
    }
};

BOOST_FIXTURE_TEST_SUITE(freeze_registry_harness_tests, FreezeChainSetup)

// ---------------------------------------------------------------------------
// R1 REGRESSION (the load-bearing test): a non-authority forged FREEZE op,
// ignored at connect, must NOT be inverted at disconnect. Proves the
// DisconnectBlock reverse guard (OP_5 + height) and fails if it regresses.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(r1_reverse_skips_non_authority_freeze)
{
    // X stands for a legitimately-frozen USDSOQ outpoint (seed directly; how it got
    // frozen is irrelevant to the reverse-guard property).
    COutPoint X(uint256S("0xfeed1111feed1111feed1111feed1111feed1111feed1111feed1111feed1111"), 0);
    BOOST_REQUIRE(pcoinsdbview->WriteFrozenOutpoint(X));
    BOOST_REQUIRE(pcoinsdbview->IsFrozenOutpoint(X));

    // Mine a block B with a NON-authority tx forging FREEZE[op=FREEZE][X].
    CMutableTransaction forged = BuildForgedFreezeTx(coinbaseTxns[0], FREEZE_OP_FREEZE, X);
    std::vector<CMutableTransaction> txns{forged};
    CBlock B = CreateAndProcessBlock(txns, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == B.GetHash(),
        "block B with the forged-freeze tx must connect");

    // At connect, APPLY ignored the forged op (no OP_5 / authority gate) → X still frozen.
    BOOST_CHECK_MESSAGE(pcoinsdbview->IsFrozenOutpoint(X),
        "connect: non-authority forged FREEZE must not be applied — X stays frozen");

    // Reorg B out → triggers DisconnectBlock(B).
    {
        LOCK(cs_main);
        CValidationState state;
        BlockMap::iterator it = mapBlockIndex.find(B.GetHash());
        BOOST_REQUIRE(it != mapBlockIndex.end());
        InvalidateBlock(state, Params(), it->second);
        ActivateBestChain(state, Params());
    }
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() != B.GetHash(), "B must be disconnected");

    // R1: the reverse guard skipped the non-OP_5 forged tx, so it did NOT erase X.
    // Without the guard, DisconnectBlock would EraseFrozenOutpoint(X) → freeze bypass.
    BOOST_CHECK_MESSAGE(pcoinsdbview->IsFrozenOutpoint(X),
        "R1: DisconnectBlock must NOT invert a non-authority forged FREEZE — X must remain frozen");

    pcoinsdbview->EraseFrozenOutpoint(X); // cleanup
}

// ---------------------------------------------------------------------------
// Griefing direction: a non-authority forged UNFREEZE op must NOT phantom-freeze
// a victim on disconnect (reverse of UNFREEZE = Write). Same guard, other direction.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(r1_reverse_skips_non_authority_unfreeze)
{
    COutPoint victim(uint256S("0xv1ct1m22v1ct1m22v1ct1m22v1ct1m22v1ct1m22v1ct1m22v1ct1m22v1ct1m22"), 3);
    BOOST_REQUIRE(!pcoinsdbview->IsFrozenOutpoint(victim));

    CMutableTransaction forged = BuildForgedFreezeTx(coinbaseTxns[1], FREEZE_OP_UNFREEZE, victim);
    std::vector<CMutableTransaction> txns{forged};
    CBlock B = CreateAndProcessBlock(txns, coinbaseSpk);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == B.GetHash());

    {
        LOCK(cs_main);
        CValidationState state;
        BlockMap::iterator it = mapBlockIndex.find(B.GetHash());
        BOOST_REQUIRE(it != mapBlockIndex.end());
        InvalidateBlock(state, Params(), it->second);
        ActivateBestChain(state, Params());
    }

    // R1: reverse of a non-authority UNFREEZE must NOT write victim into the set.
    BOOST_CHECK_MESSAGE(!pcoinsdbview->IsFrozenOutpoint(victim),
        "R1: DisconnectBlock must NOT phantom-freeze a victim from a non-authority forged UNFREEZE");
}

BOOST_AUTO_TEST_SUITE_END()
