// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// dilithium_keyhash_committed_tests.cpp
// -----------------------------------------------------------------------------
// COMMITTED-PATH test vectors for OP_CHECKDILITHIUMKEYHASH (0xb6 / SOQ-COV-013).
//
// WHY THIS FILE EXISTS (read before editing the handler):
//
//   The first cut of dilithium_keyhash_tests.cpp drove the opcode with a bare
//   EvalScript + SIGVERSION_BASE and PRE-LOADED the keyhash onto the stack as a
//   spender-supplied item. That never exercises the real spend path and — worse —
//   it bakes in the wrong threat model: if the keyhash is witness-supplied, a
//   thief just supplies SHA256(theirOwnKey) and the "key binding" is vacuous.
//
//   For OP_CHECKDILITHIUMKEYHASH to bind a v6 output to a SPECIFIC Dilithium key,
//   the keyhash MUST be COMMITTED inside the witnessScript (which is itself
//   committed by SHA256 in the v6 program). A committed `<keyhash>` push always
//   lands on TOP of the witness-supplied {sig, pubkey} at the moment the opcode
//   executes. Therefore the correct stack layout at execution is:
//
//       stacktop(-1) = keyhash   (pushed by the script  -> COMMITTED)
//       stacktop(-2) = pubkey    (from the witness)
//       stacktop(-3) = sig       (from the witness)
//
//   ...and the opcode must POP ALL THREE (push nothing), so it composes into a
//   k-of-n by chaining checks and ending the script with OP_1 for the clean-stack
//   rule:  <keyhashB> OP_CHECKDILITHIUMKEYHASH <keyhashA> OP_CHECKDILITHIUMKEYHASH OP_1
//
//   See OPCODE_SPEC_DILITHIUM_MULTISIG.md (soqucoin-ops/lightning) §3, §5, §8.
//
// RELATIONSHIP TO THE HANDLER:
//
//   These tests are written against the CORRECTED handler semantics (keyhash at
//   stacktop(-1), pubkey at -2, sig at -3, pops all 3). The handler was fixed in
//   the same session that added this file — see SOQ-COV-013 in the registry.
//
// WHAT THESE COVER THAT THE BARE-EVALSCRIPT TESTS DID NOT:
//   A) single-key committed round-trip  through real v6 VerifyScript  (SIGHASH_ALL)
//   B) 2-of-2  committed round-trip      through real v6 VerifyScript  (SIGHASH_ALL)
//   C) 2-of-2  committed round-trip      with SIGHASH_ANYPREVOUTANYSCRIPT (0x42)
//        -> the eLTOO update-supersession path this primitive was built for
//   D) SUBSTITUTION ATTACK: commit Alice's keyhash, spend with Mallory's key+sig
//        -> MUST fail at the keyhash check (the load-bearing security property)
//   E) OUTPUT TAMPER: valid sigs, then mutate the spending tx outputs
//        -> MUST fail (sig is bound to the tx via the sighash CheckSig recomputes)
//
// To enable: add `test/dilithium_keyhash_committed_tests.cpp` to BITCOIN_TESTS in
// src/Makefile.test.include, then:
//   src/test/test_soqucoin --run_test=dilithium_keyhash_committed_tests --log_level=message

#include "hash.h"
#include "key.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_bitcoin.h"
#include "crypto/sha256.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(dilithium_keyhash_committed_tests, BasicTestingSetup)

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// V6 P2WSH-Dilithium scriptPubKey: OP_6 <SHA256(witnessScript)>  (34 bytes total).
// (Same construction as covenant_tests.cpp / lightning_script_tests.cpp.)
static CScript MakeV6ScriptPubKey(const CScript& witnessScript)
{
    uint256 scriptHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(scriptHash.begin());
    CScript spk;
    spk << OP_6;
    spk << std::vector<unsigned char>(scriptHash.begin(), scriptHash.end());
    return spk;
}

// SHA256(pubkey) over the raw 1312-byte ML-DSA-44 pubkey — the value committed
// in-script. Mirrors exactly what the handler hashes (it strips a 0x00 prefix
// first, so we always hash the 1312-byte form).
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

// Produce a CheckSig-consumable signature: raw 2420-byte ML-DSA-44 sig over the
// 32-byte sighash, with the 1-byte hashtype appended.
//
//   - CheckSig does: nHashType = sig.back(); strip it; verify the raw sig over
//     SignatureHash(witnessScript, tx, nIn, nHashType, amount, WITNESS_V0).
//   - CKey::Sign signs the raw 32-byte digest directly (FIPS 204, empty context),
//     so — unlike CSFS — we sign the sighash itself, NOT Hash(sighash).
//   - scriptCode = the FULL witnessScript (that is the `script` CheckSig receives
//     inside EvalScript), so SIGHASH_ALL commits to the whole script.
static std::vector<unsigned char> SignForKeyhash(const CKey& key,
                                                 const CScript& witnessScript,
                                                 const CTransaction& tx,
                                                 unsigned int nIn,
                                                 const CAmount& amount,
                                                 int hashType)
{
    uint256 sighash = SignatureHash(witnessScript, tx, nIn, hashType, amount,
                                    SIGVERSION_WITNESS_V0, nullptr);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    BOOST_REQUIRE_EQUAL(sig.size(), 2420u);
    sig.push_back(static_cast<unsigned char>(hashType));
    return sig;
}

// Flags for the active v6 + keyhash path (BIP9-active in this harness).
static unsigned int V6KeyhashFlags()
{
    return SCRIPT_VERIFY_WITNESS
         | SCRIPT_VERIFY_P2WSH_DILITHIUM   // activate v6 covenant dispatch
         | SCRIPT_VERIFY_DILITHIUM_KEYHASH // activate OP_CHECKDILITHIUMKEYHASH
         | SCRIPT_VERIFY_APO               // allow 0x41/0x42 (eLTOO rebinding)
         | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
         | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
}

// Build a funding tx whose single output pays the given v6 spk, and a spend tx
// that consumes it. Returns the spend tx (caller signs + attaches the witness).
static CMutableTransaction MakeSpendOf(const CScript& fundingSpk,
                                       const CAmount& amount,
                                       const CScript& spendOutScript,
                                       uint32_t spendSequence,
                                       uint32_t spendLockTime)
{
    CMutableTransaction fundTx;
    fundTx.nVersion = 2;
    fundTx.nLockTime = 0;
    CTxIn cb; cb.prevout.SetNull(); cb.nSequence = CTxIn::SEQUENCE_FINAL;
    fundTx.vin.push_back(cb);
    CTxOut fo; fo.nValue = amount; fo.scriptPubKey = fundingSpk;
    fundTx.vout.push_back(fo);

    CMutableTransaction spendTx;
    spendTx.nVersion = 2;
    spendTx.nLockTime = spendLockTime;
    CTxIn in;
    in.prevout.hash = CTransaction(fundTx).GetHash();
    in.prevout.n = 0;
    in.nSequence = spendSequence;
    spendTx.vin.push_back(in);
    CTxOut o; o.nValue = amount; o.scriptPubKey = spendOutScript;
    spendTx.vout.push_back(o);
    return spendTx;
}

// ============================================================================
// A) Single-key committed round-trip — SIGHASH_ALL
//    witnessScript: <keyhashA> OP_CHECKDILITHIUMKEYHASH OP_1
//    eval items    : [ sigA, pubkeyA ]
// ============================================================================
BOOST_AUTO_TEST_CASE(committed_single_key_roundtrip)
{
    CKey alice; alice.MakeNewKey(true);
    CPubKey alicePk = alice.GetPubKey();
    BOOST_REQUIRE(alicePk.IsValid());
    std::vector<unsigned char> alicePkBytes(alicePk.begin(), alicePk.end());
    BOOST_REQUIRE_EQUAL(alicePkBytes.size(), 1312u);

    CScript ws;
    ws << KeyHash(alicePkBytes) << OP_CHECKDILITHIUMKEYHASH << OP_1;
    CScript spk = MakeV6ScriptPubKey(ws);
    BOOST_REQUIRE_EQUAL(spk.size(), 34u);

    const CAmount amount = 50 * COIN;
    CMutableTransaction spend =
        MakeSpendOf(spk, amount, CScript() << OP_TRUE, CTxIn::SEQUENCE_FINAL, 0);
    CTransaction ctx(spend);

    std::vector<unsigned char> sigA =
        SignForKeyhash(alice, ws, ctx, 0, amount, SIGHASH_ALL);

    CScriptWitness w;
    w.stack.push_back(sigA);                          // eval[-3] sig
    w.stack.push_back(alicePkBytes);                  // eval[-2] pubkey
    w.stack.push_back(std::vector<unsigned char>(ws.begin(), ws.end())); // witnessScript
    w.stack.push_back(Prefixed(alicePkBytes));        // trailing 0x00||pk

    ScriptError serr = SCRIPT_ERR_OK;
    TransactionSignatureChecker checker(&ctx, 0, amount);
    bool ok = VerifyScript(CScript(), spk, &w, V6KeyhashFlags(), checker, &serr);

    BOOST_CHECK_MESSAGE(ok,
        "single-key committed keyhash must verify through v6; serror=" << serr);
}

// ============================================================================
// B) 2-of-2 committed round-trip — SIGHASH_ALL
//    witnessScript: <keyhashB> OP_CHECKDILITHIUMKEYHASH
//                   <keyhashA> OP_CHECKDILITHIUMKEYHASH OP_1
//    eval items    : [ sigA, pubkeyA, sigB, pubkeyB ]  (B on top -> checked first)
// ============================================================================
BOOST_AUTO_TEST_CASE(committed_2of2_roundtrip)
{
    CKey alice, bob;
    alice.MakeNewKey(true);
    bob.MakeNewKey(true);
    CPubKey alicePk = alice.GetPubKey(), bobPk = bob.GetPubKey();
    BOOST_REQUIRE(alicePk.IsValid() && bobPk.IsValid());
    std::vector<unsigned char> alicePkBytes(alicePk.begin(), alicePk.end());
    std::vector<unsigned char> bobPkBytes(bobPk.begin(), bobPk.end());

    CScript ws;
    ws << KeyHash(bobPkBytes)   << OP_CHECKDILITHIUMKEYHASH   // checks top: B
       << KeyHash(alicePkBytes) << OP_CHECKDILITHIUMKEYHASH   // then:      A
       << OP_1;
    CScript spk = MakeV6ScriptPubKey(ws);

    const CAmount amount = 100 * COIN;
    CMutableTransaction spend =
        MakeSpendOf(spk, amount, CScript() << OP_TRUE, CTxIn::SEQUENCE_FINAL, 0);
    CTransaction ctx(spend);

    // Both signers sign the SAME sighash (CheckSig uses scriptCode=full ws,
    // same hashtype) — just with different keys.
    std::vector<unsigned char> sigA = SignForKeyhash(alice, ws, ctx, 0, amount, SIGHASH_ALL);
    std::vector<unsigned char> sigB = SignForKeyhash(bob,   ws, ctx, 0, amount, SIGHASH_ALL);

    CScriptWitness w;
    w.stack.push_back(sigA);          // eval[0]
    w.stack.push_back(alicePkBytes);  // eval[1]
    w.stack.push_back(sigB);          // eval[2]
    w.stack.push_back(bobPkBytes);    // eval[3]  (top -> consumed by 1st check)
    w.stack.push_back(std::vector<unsigned char>(ws.begin(), ws.end()));
    w.stack.push_back(Prefixed(alicePkBytes));

    ScriptError serr = SCRIPT_ERR_OK;
    TransactionSignatureChecker checker(&ctx, 0, amount);
    bool ok = VerifyScript(CScript(), spk, &w, V6KeyhashFlags(), checker, &serr);

    BOOST_CHECK_MESSAGE(ok,
        "2-of-2 committed keyhash must verify through v6; serror=" << serr);
}

// ============================================================================
// C) 2-of-2 committed round-trip — SIGHASH_ANYPREVOUTANYSCRIPT (0x42)
//    The eLTOO update-supersession path: APO rebinding + key-committed 2-of-2.
// ============================================================================
BOOST_AUTO_TEST_CASE(committed_2of2_apo_anyprevoutanyscript)
{
    CKey alice, bob;
    alice.MakeNewKey(true);
    bob.MakeNewKey(true);
    CPubKey alicePk = alice.GetPubKey();
    CPubKey bobPk = bob.GetPubKey();
    std::vector<unsigned char> alicePkBytes(alicePk.begin(), alicePk.end());
    std::vector<unsigned char> bobPkBytes(bobPk.begin(), bobPk.end());

    CScript ws;
    ws << KeyHash(bobPkBytes)   << OP_CHECKDILITHIUMKEYHASH
       << KeyHash(alicePkBytes) << OP_CHECKDILITHIUMKEYHASH
       << OP_1;
    CScript spk = MakeV6ScriptPubKey(ws);

    const CAmount amount = 100 * COIN;
    CMutableTransaction spend =
        MakeSpendOf(spk, amount, CScript() << OP_TRUE, 0xfffffffe, 101 /*state*/);
    CTransaction ctx(spend);

    const int apo = SIGHASH_ANYPREVOUTANYSCRIPT; // 0x42
    std::vector<unsigned char> sigA = SignForKeyhash(alice, ws, ctx, 0, amount, apo);
    std::vector<unsigned char> sigB = SignForKeyhash(bob,   ws, ctx, 0, amount, apo);

    CScriptWitness w;
    w.stack.push_back(sigA);
    w.stack.push_back(alicePkBytes);
    w.stack.push_back(sigB);
    w.stack.push_back(bobPkBytes);
    w.stack.push_back(std::vector<unsigned char>(ws.begin(), ws.end()));
    w.stack.push_back(Prefixed(alicePkBytes));

    ScriptError serr = SCRIPT_ERR_OK;
    TransactionSignatureChecker checker(&ctx, 0, amount);
    bool ok = VerifyScript(CScript(), spk, &w, V6KeyhashFlags(), checker, &serr);

    BOOST_CHECK_MESSAGE(ok,
        "2-of-2 committed keyhash with APO 0x42 must verify (eLTOO update path); serror=" << serr);
}

// ============================================================================
// D) SUBSTITUTION ATTACK  (the load-bearing security test)
//    Script commits ALICE's keyhash. Attacker Mallory presents HER OWN key+sig.
//    The keyhash check (SHA256(mallory) != aliceKeyhash) MUST reject.
//    If this passes, the "key binding" is vacuous and funds are stealable.
// ============================================================================
BOOST_AUTO_TEST_CASE(committed_substitution_attack_rejected)
{
    CKey alice, mallory;
    alice.MakeNewKey(true);
    mallory.MakeNewKey(true);
    CPubKey alicePk = alice.GetPubKey();
    CPubKey malloryPk = mallory.GetPubKey();
    std::vector<unsigned char> alicePkBytes(alicePk.begin(), alicePk.end());
    std::vector<unsigned char> malloryPkBytes(malloryPk.begin(), malloryPk.end());

    // Output is locked to ALICE's key.
    CScript ws;
    ws << KeyHash(alicePkBytes) << OP_CHECKDILITHIUMKEYHASH << OP_1;
    CScript spk = MakeV6ScriptPubKey(ws);

    const CAmount amount = 50 * COIN;
    CMutableTransaction spend =
        MakeSpendOf(spk, amount, CScript() << OP_TRUE, CTxIn::SEQUENCE_FINAL, 0);
    CTransaction ctx(spend);

    // Mallory signs with her own key over a valid sighash — her signature is
    // internally valid for HER key, but her key is not the committed one.
    std::vector<unsigned char> mallorySig =
        SignForKeyhash(mallory, ws, ctx, 0, amount, SIGHASH_ALL);

    CScriptWitness w;
    w.stack.push_back(mallorySig);                       // sig (Mallory)
    w.stack.push_back(malloryPkBytes);                   // pubkey (Mallory)
    w.stack.push_back(std::vector<unsigned char>(ws.begin(), ws.end()));
    w.stack.push_back(Prefixed(malloryPkBytes));

    ScriptError serr = SCRIPT_ERR_OK;
    TransactionSignatureChecker checker(&ctx, 0, amount);
    bool ok = VerifyScript(CScript(), spk, &w, V6KeyhashFlags(), checker, &serr);

    BOOST_CHECK_MESSAGE(!ok,
        "SUBSTITUTION ATTACK must be rejected: Mallory's key does not match the committed keyhash");
    BOOST_CHECK_MESSAGE(serr == SCRIPT_ERR_CHECKDILITHIUMKEYHASH,
        "substitution must fail at the keyhash check; got serror=" << serr);
}

// ============================================================================
// E) OUTPUT TAMPER  (proves tx-binding via the sighash)
//    Sign a valid spend, then mutate the spending tx's output value and reuse
//    the same signature. CheckSig recomputes the sighash over the tampered tx,
//    so verification MUST fail.
// ============================================================================
BOOST_AUTO_TEST_CASE(committed_output_tamper_rejected)
{
    CKey alice; alice.MakeNewKey(true);
    CPubKey alicePk = alice.GetPubKey();
    std::vector<unsigned char> alicePkBytes(alicePk.begin(), alicePk.end());

    CScript ws;
    ws << KeyHash(alicePkBytes) << OP_CHECKDILITHIUMKEYHASH << OP_1;
    CScript spk = MakeV6ScriptPubKey(ws);

    const CAmount amount = 50 * COIN;

    // Honest spend: 50 SOQ out. Sign it.
    CMutableTransaction honest =
        MakeSpendOf(spk, amount, CScript() << OP_TRUE, CTxIn::SEQUENCE_FINAL, 0);
    CTransaction ctxHonest(honest);
    std::vector<unsigned char> sigA =
        SignForKeyhash(alice, ws, ctxHonest, 0, amount, SIGHASH_ALL);

    // Tamper: redirect value (bump the output) but reuse the honest signature.
    CMutableTransaction tampered = honest;
    tampered.vout[0].nValue = amount + 5 * COIN;
    CTransaction ctxTampered(tampered);

    CScriptWitness w;
    w.stack.push_back(sigA);                       // signature is bound to ctxHonest
    w.stack.push_back(alicePkBytes);
    w.stack.push_back(std::vector<unsigned char>(ws.begin(), ws.end()));
    w.stack.push_back(Prefixed(alicePkBytes));

    ScriptError serr = SCRIPT_ERR_OK;
    TransactionSignatureChecker checker(&ctxTampered, 0, amount); // verify vs TAMPERED tx
    bool ok = VerifyScript(CScript(), spk, &w, V6KeyhashFlags(), checker, &serr);

    BOOST_CHECK_MESSAGE(!ok,
        "OUTPUT TAMPER must be rejected: signature is bound to the original outputs via the sighash");
    BOOST_CHECK_MESSAGE(serr == SCRIPT_ERR_CHECKDILITHIUMKEYHASH,
        "tampered-output spend must fail at the CheckSig step; got serror=" << serr);
}

// ============================================================================
// F) DETERMINISTIC CROSS-VECTOR vs soq-lightning-sdk (test/keyhash.test.mjs)
//    Pins witnessScript assembly + v6 scriptPubKey + APO 0x42 sighash to the SDK.
//    Keygen-independent: built from the two committed keyhashes, no signing.
//    The amount MUST be 1 COIN to match the SDK (AMOUNT = 100_000_000).
// ============================================================================
BOOST_AUTO_TEST_CASE(committed_sdk_crossvector)
{
    // --- keyhashes from the SDK vector (seeds A=0x11*32, B=0x22*32) ---
    const std::vector<unsigned char> khA =
        ParseHex("a8fb234f71d54297c08936be4acd1e6d21c5bc0143df1a7e94d251f11717682a");
    const std::vector<unsigned char> khB =
        ParseHex("34f9a34efa21ddd744e62a83c126f2652c459a63a290af00a3131da57a339c25");
    BOOST_REQUIRE_EQUAL(khA.size(), 32u);
    BOOST_REQUIRE_EQUAL(khB.size(), 32u);

    // --- witnessScript: <khB> OP_CDKH <khA> OP_CDKH OP_1  (B committed first) ---
    CScript ws;
    ws << khB << OP_CHECKDILITHIUMKEYHASH << khA << OP_CHECKDILITHIUMKEYHASH << OP_1;
    CScript spk = MakeV6ScriptPubKey(ws);

    // --- the eLTOO update tx the SDK signs (version 2, locktime 101, amount 1 COIN) ---
    // For 0x42 the prevout + input sequence are NOT committed, so their exact values
    // do not affect the sighash; only version/amount/outputs/locktime/hashtype do.
    const CAmount amount = COIN; // == SDK AMOUNT 100_000_000  (NOT 100*COIN)

    CMutableTransaction spend =
        MakeSpendOf(spk, amount, CScript() << OP_TRUE, 0xfffffffe, 101 /*state*/);
    CTransaction ctx(spend);

    uint256 sighash = SignatureHash(ws, ctx, 0, SIGHASH_ANYPREVOUTANYSCRIPT,
                                    amount, SIGVERSION_WITNESS_V0, nullptr);

    // --- assert byte-equality with the SDK ---
    const std::string EXPECT_WS  =
        "2034f9a34efa21ddd744e62a83c126f2652c459a63a290af00a3131da57a339c25b6"
        "20a8fb234f71d54297c08936be4acd1e6d21c5bc0143df1a7e94d251f11717682ab651";
    const std::string EXPECT_SPK =
        "56208a0fa8a6e1cf96081b999ab7323df717ee3d2f57a837428b24405cb5e3ed1be5";
    const std::string EXPECT_SH  =
        "b3275466d41b3e4eefe04653941a45ad5f65a73af35fb23af86c221421e8ab55";

    const std::string gotWs  = HexStr(ws.begin(), ws.end());
    const std::string gotSpk = HexStr(spk.begin(), spk.end());
    const std::string gotSh  = HexStr(sighash.begin(), sighash.end());

    BOOST_TEST_MESSAGE("witnessScript=" << gotWs);
    BOOST_TEST_MESSAGE("scriptPubKey =" << gotSpk);
    BOOST_TEST_MESSAGE("apo42_sighash=" << gotSh);

    BOOST_CHECK_EQUAL(gotWs,  EXPECT_WS);   // COV-013 script assembly
    BOOST_CHECK_EQUAL(gotSpk, EXPECT_SPK);  // v6 program derivation
    BOOST_CHECK_EQUAL(gotSh,  EXPECT_SH);   // APO 0x42 sighash + SOQ output serialization
}

BOOST_AUTO_TEST_SUITE_END()
