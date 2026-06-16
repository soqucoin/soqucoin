// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// usdsoq_v7_holding_tests.cpp — witness-v7 USDSOQ holding (CTxOut migration Phase 3, increment 2).
//
// A v7 USDSOQ holding (OP_7 <SHA256(pubkey)>) holds USDSOQ value and is spent EXACTLY like a v1
// single-key Dilithium output — the handler reuses the audited v1 verify path; the witness version
// is the asset discriminator (CTxOut::IsUSDSOQ). These tests pin the spend handler in situ via
// VerifyScript: valid owner spend passes (flag on), wrong key fails, anyone-can-spend when the
// USDSOQ flag is off (soft-fork safe), and IsUSDSOQ() follows the version.

#include "key.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "consensus/usdsoq.h"
#include "crypto/sha256.h"
#include "uint256.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace {

// v7 USDSOQ holding scriptPubKey: OP_7 <SHA256(rawPubkey)>  (34 bytes).
static CScript MakeV7Spk(const std::vector<unsigned char>& rawPubkey)
{
    uint256 h;
    CSHA256().Write(rawPubkey.data(), rawPubkey.size()).Finalize(h.begin());
    CScript spk;
    spk << OP_7 << std::vector<unsigned char>(h.begin(), h.end());
    return spk;
}

static std::vector<unsigned char> Prefixed(const std::vector<unsigned char>& raw)
{
    std::vector<unsigned char> out; out.push_back(0x00);
    out.insert(out.end(), raw.begin(), raw.end());
    return out;
}

// Sign the witness-v0 sighash over scriptCode and append the hashtype byte.
static std::vector<unsigned char> SignV7(const CKey& key, const CScript& scriptCode,
    const CTransaction& tx, const CAmount& amount, int hashType)
{
    uint256 sighash = SignatureHash(scriptCode, tx, 0, hashType, amount, SIGVERSION_WITNESS_V0, nullptr);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    sig.push_back((unsigned char)hashType);
    return sig;
}

// A tx spending a (notional) v7 outpoint at index 0.
static CMutableTransaction SpendTx()
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    CTxIn in; in.prevout = COutPoint(uint256S("0x77"), 0); in.nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin.push_back(in);
    CTxOut o; o.nValue = 50 * COIN; o.scriptPubKey = CScript() << OP_TRUE; o.nVisibility = 0; o.nAssetType = 0;
    tx.vout.push_back(o);
    return tx;
}

const unsigned int V7_FLAGS = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_USDSOQ;

} // namespace

BOOST_FIXTURE_TEST_SUITE(usdsoq_v7_holding_tests, BasicTestingSetup)

// A v7 USDSOQ holding spends with a valid owner Dilithium sig (USDSOQ active).
BOOST_AUTO_TEST_CASE(v7_holding_valid_spend)
{
    CKey owner; owner.MakeNewKey(true);
    std::vector<unsigned char> pk(owner.GetPubKey().begin(), owner.GetPubKey().end());
    BOOST_REQUIRE_EQUAL(pk.size(), 1312u);

    CScript spk = MakeV7Spk(pk);
    BOOST_REQUIRE_EQUAL(spk.size(), 34u);
    BOOST_REQUIRE_EQUAL(spk[0], OP_7);

    const CAmount amount = 50 * COIN;
    CMutableTransaction spend = SpendTx();
    CTransaction ctx(spend);

    std::vector<unsigned char> sig = SignV7(owner, spk, ctx, amount, SIGHASH_ALL);
    CScriptWitness w;
    w.stack.push_back(sig);
    w.stack.push_back(Prefixed(pk));   // 0x00||pubkey (FIPS 204), as v1 expects

    ScriptError serr = SCRIPT_ERR_OK;
    TransactionSignatureChecker checker(&ctx, 0, amount);
    bool ok = VerifyScript(CScript(), spk, &w, V7_FLAGS, checker, &serr);
    BOOST_CHECK_MESSAGE(ok, "v7 USDSOQ holding must verify with the owner's Dilithium sig; serror=" << serr);
}

// Wrong key → rejected (the holding is bound to its owner key, exactly like v1).
BOOST_AUTO_TEST_CASE(v7_holding_wrong_key_rejected)
{
    CKey owner, mallory; owner.MakeNewKey(true); mallory.MakeNewKey(true);
    std::vector<unsigned char> ownerPk(owner.GetPubKey().begin(), owner.GetPubKey().end());
    std::vector<unsigned char> malloryPk(mallory.GetPubKey().begin(), mallory.GetPubKey().end());

    CScript spk = MakeV7Spk(ownerPk);   // locked to owner
    const CAmount amount = 50 * COIN;
    CMutableTransaction spend = SpendTx();
    CTransaction ctx(spend);

    // Mallory signs with her own key + presents her own pubkey.
    std::vector<unsigned char> mSig = SignV7(mallory, spk, ctx, amount, SIGHASH_ALL);
    CScriptWitness w;
    w.stack.push_back(mSig);
    w.stack.push_back(Prefixed(malloryPk));

    ScriptError serr = SCRIPT_ERR_OK;
    TransactionSignatureChecker checker(&ctx, 0, amount);
    bool ok = VerifyScript(CScript(), spk, &w, V7_FLAGS, checker, &serr);
    BOOST_CHECK_MESSAGE(!ok, "v7 holding must reject a non-owner key (SHA256(mallory) != program)");
}

// Soft-fork safety: when SCRIPT_VERIFY_USDSOQ is NOT set, v7 is anyone-can-spend.
BOOST_AUTO_TEST_CASE(v7_holding_anyone_can_spend_when_inactive)
{
    CKey owner; owner.MakeNewKey(true);
    std::vector<unsigned char> pk(owner.GetPubKey().begin(), owner.GetPubKey().end());
    CScript spk = MakeV7Spk(pk);
    CMutableTransaction spend = SpendTx();
    CTransaction ctx(spend);

    // A junk witness — must still pass when the flag is off (program not validated).
    CScriptWitness w;
    w.stack.push_back(std::vector<unsigned char>{0x00});
    w.stack.push_back(std::vector<unsigned char>{0x00});

    ScriptError serr = SCRIPT_ERR_OK;
    TransactionSignatureChecker checker(&ctx, 0, 50 * COIN);
    bool ok = VerifyScript(CScript(), spk, &w, SCRIPT_VERIFY_WITNESS /* no USDSOQ */, checker, &serr);
    BOOST_CHECK_MESSAGE(ok, "v7 must be anyone-can-spend before USDSOQ activation (soft-fork safe); serror=" << serr);
}

// Asset classification follows the witness version: a v7 output is USDSOQ with no byte set.
BOOST_AUTO_TEST_CASE(v7_isusdsoq_by_version)
{
    CKey k; k.MakeNewKey(true);
    std::vector<unsigned char> pk(k.GetPubKey().begin(), k.GetPubKey().end());

    CTxOut v7; v7.nValue = 1000; v7.scriptPubKey = MakeV7Spk(pk); v7.nVisibility = 0; v7.nAssetType = 0;
    BOOST_CHECK(v7.IsV7USDSOQHolding());
    BOOST_CHECK(v7.IsUSDSOQ());        // USDSOQ by version, nAssetType byte == 0
    BOOST_CHECK(!v7.IsNativeSOQ());

    // A plain v1 output is SOQ unless the legacy byte is set (transition recognition).
    CScript v1; v1 << OP_1 << std::vector<unsigned char>(32, 0xcd);
    CTxOut soq; soq.nValue = 1000; soq.scriptPubKey = v1; soq.nVisibility = 0; soq.nAssetType = 0;
    BOOST_CHECK(!soq.IsUSDSOQ());
    BOOST_CHECK(soq.IsNativeSOQ());
}

BOOST_AUTO_TEST_SUITE_END()
