// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-I005: USDSOQ Authority Signature Verification Tests
// Tests the M-of-N Dilithium authority verification added to ConnectBlock
// in Phase 1, the witness stack helpers, the sighash computation, and
// the usdsoqsigntx RPC signing pipeline.
//
// These tests exercise REAL Dilithium keypairs — no mocks.

#include "consensus/usdsoq.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "test/test_bitcoin.h"
#include "uint256.h"

extern "C" {
#include "crypto/dilithium/api.h"
}

#include <boost/test/unit_test.hpp>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(usdsoq_authority_tests, BasicTestingSetup)

// =========================================================================
// Helper: Generate a Dilithium keypair
// =========================================================================
struct DilithiumKeypair {
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;

    DilithiumKeypair() : pk(pqcrystals_dilithium2_PUBLICKEYBYTES),
                         sk(pqcrystals_dilithium2_SECRETKEYBYTES)
    {
        int ret = pqcrystals_dilithium2_ref_keypair(pk.data(), sk.data());
        assert(ret == 0);
    }
};

// Helper: Sign a message with a Dilithium secret key
static std::vector<uint8_t> DilithiumSign(
    const std::vector<uint8_t>& msg,
    const std::vector<uint8_t>& sk)
{
    std::vector<uint8_t> sig(pqcrystals_dilithium2_BYTES);
    size_t siglen = 0;
    int ret = pqcrystals_dilithium2_ref_signature(
        sig.data(), &siglen,
        msg.data(), msg.size(),
        nullptr, 0,  // empty FIPS 204 context
        sk.data());
    assert(ret == 0);
    sig.resize(siglen);
    return sig;
}

// Helper: Build a simple test message (simulates a sighash)
static std::vector<uint8_t> TestMessage(uint8_t fill = 0x42)
{
    return std::vector<uint8_t>(32, fill);
}

// Helper: Build a fake 2420-byte blob (NOT a valid Dilithium signature)
static std::vector<uint8_t> FakeSignature(uint8_t fill = 0xDE)
{
    return std::vector<uint8_t>(DILITHIUM_SIG_SIZE, fill);
}

// Helper: Build an OP_5 <32-byte hash> authority script
static CScript MakeAuthorityScript(const std::vector<std::vector<uint8_t>>& keys)
{
    uint256 keyHash = ComputeAuthorityKeyHash(keys);
    CScript script;
    script << OP_5;
    script << std::vector<unsigned char>(keyHash.begin(), keyHash.end());
    return script;
}

// =========================================================================
// 1. AUTHORITY INITIALIZATION WITH REAL KEYS
// =========================================================================

BOOST_AUTO_TEST_CASE(authority_init_real_keypairs)
{
    DilithiumKeypair k0, k1, k2;

    CUSDSOQAuthority auth;
    std::vector<std::vector<uint8_t>> keys = {k0.pk, k1.pk, k2.pk};
    BOOST_CHECK(auth.Initialize(keys, 2));
    BOOST_CHECK(auth.IsInitialized());
    BOOST_CHECK_EQUAL(auth.GetThreshold(), 2u);
    BOOST_CHECK_EQUAL(auth.GetKeyCount(), 3u);
}

// =========================================================================
// 2. VALID 2-of-3 SIGNATURE VERIFICATION
// =========================================================================

BOOST_AUTO_TEST_CASE(verify_valid_2of3_sigs)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    auto msg = TestMessage();

    // Sign with keys 0 and 1 (2-of-3)
    auto sig0 = DilithiumSign(msg, k0.sk);
    auto sig1 = DilithiumSign(msg, k1.sk);

    BOOST_CHECK(auth.VerifyAuthoritySignatures(msg, {sig0, sig1}));
}

BOOST_AUTO_TEST_CASE(verify_valid_2of3_different_key_pair)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    auto msg = TestMessage();

    // Sign with keys 1 and 2 (different combination, still 2-of-3)
    auto sig1 = DilithiumSign(msg, k1.sk);
    auto sig2 = DilithiumSign(msg, k2.sk);

    BOOST_CHECK(auth.VerifyAuthoritySignatures(msg, {sig1, sig2}));
}

BOOST_AUTO_TEST_CASE(verify_valid_3of3_sigs)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    auto msg = TestMessage();

    // All 3 keys sign — exceeds threshold, still valid
    auto sig0 = DilithiumSign(msg, k0.sk);
    auto sig1 = DilithiumSign(msg, k1.sk);
    auto sig2 = DilithiumSign(msg, k2.sk);

    BOOST_CHECK(auth.VerifyAuthoritySignatures(msg, {sig0, sig1, sig2}));
}

// =========================================================================
// 3. INVALID SIGNATURES — RANDOM BLOBS
// =========================================================================

BOOST_AUTO_TEST_CASE(reject_fake_sigs_random_blobs)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    auto msg = TestMessage();

    // Two 2420-byte random blobs — structurally valid but cryptographically garbage
    auto fake0 = FakeSignature(0xAA);
    auto fake1 = FakeSignature(0xBB);

    BOOST_CHECK(!auth.VerifyAuthoritySignatures(msg, {fake0, fake1}));
}

BOOST_AUTO_TEST_CASE(reject_one_real_one_fake)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    auto msg = TestMessage();

    // One valid sig + one fake blob = only 1 valid, below threshold 2
    auto sig0 = DilithiumSign(msg, k0.sk);
    auto fake = FakeSignature(0xCC);

    BOOST_CHECK(!auth.VerifyAuthoritySignatures(msg, {sig0, fake}));
}

// =========================================================================
// 4. BELOW THRESHOLD — 1-of-3 REJECTED
// =========================================================================

BOOST_AUTO_TEST_CASE(reject_below_threshold_1of3)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    auto msg = TestMessage();

    // Only 1 valid sig — threshold is 2
    auto sig0 = DilithiumSign(msg, k0.sk);

    BOOST_CHECK(!auth.VerifyAuthoritySignatures(msg, {sig0}));
}

// =========================================================================
// 5. DUPLICATE KEY — SAME SIG TWICE
// =========================================================================

BOOST_AUTO_TEST_CASE(reject_duplicate_sig_same_key)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    auto msg = TestMessage();

    // Same key signs twice — bitvector should prevent double-counting
    auto sig0a = DilithiumSign(msg, k0.sk);
    auto sig0b = DilithiumSign(msg, k0.sk);

    // Even though we have 2 sigs, they're from the same key.
    // The bitvector in VerifyAuthoritySignatures marks k0 as used after
    // the first sig, so sig0b finds no unused matching key.
    // valid_count = 1, threshold = 2 → rejected.
    BOOST_CHECK(!auth.VerifyAuthoritySignatures(msg, {sig0a, sig0b}));
}

// =========================================================================
// 6. WRONG MESSAGE — SIG OVER DIFFERENT SIGHASH
// =========================================================================

BOOST_AUTO_TEST_CASE(reject_sig_wrong_message)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    auto correctMsg = TestMessage(0x42);
    auto wrongMsg = TestMessage(0xFF);

    // Sign over the wrong message
    auto sig0 = DilithiumSign(wrongMsg, k0.sk);
    auto sig1 = DilithiumSign(wrongMsg, k1.sk);

    // Verify against the correct message — should fail
    BOOST_CHECK(!auth.VerifyAuthoritySignatures(correctMsg, {sig0, sig1}));
}

// =========================================================================
// 7. EMPTY SIGNATURES
// =========================================================================

BOOST_AUTO_TEST_CASE(reject_empty_sig_array)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    auto msg = TestMessage();

    // Empty signature array
    std::vector<std::vector<uint8_t>> noSigs;
    BOOST_CHECK(!auth.VerifyAuthoritySignatures(msg, noSigs));
}

// =========================================================================
// 8. WRONG SIGNATURE SIZE
// =========================================================================

BOOST_AUTO_TEST_CASE(reject_wrong_sig_size)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    auto msg = TestMessage();

    // Sig with wrong size (100 bytes instead of 2420)
    std::vector<uint8_t> shortSig(100, 0xAA);
    auto sig1 = DilithiumSign(msg, k1.sk);

    BOOST_CHECK(!auth.VerifyAuthoritySignatures(msg, {shortSig, sig1}));
}

// =========================================================================
// 9. UNINITIALIZED AUTHORITY REJECTS ALL
// =========================================================================

BOOST_AUTO_TEST_CASE(reject_uninitialized_authority)
{
    CUSDSOQAuthority auth;
    // Not initialized
    BOOST_CHECK(!auth.IsInitialized());

    auto msg = TestMessage();
    auto fake = FakeSignature();
    BOOST_CHECK(!auth.VerifyAuthoritySignatures(msg, {fake}));
}

// =========================================================================
// 10. WITNESS STACK HELPERS
// =========================================================================

BOOST_AUTO_TEST_CASE(witness_tag_extraction)
{
    // Test GetUSDSOQWitnessTag
    // Witness layout: [0]=payout_sig, [1]=payout_pk, [2]=auth_tag, ...
    std::vector<std::vector<uint8_t>> stack;

    // Empty stack
    BOOST_CHECK_EQUAL(GetUSDSOQWitnessTag(stack), 0x00);

    // Only 1 item (need at least 3 for tag at index 2)
    stack.push_back({});
    BOOST_CHECK_EQUAL(GetUSDSOQWitnessTag(stack), 0x00);

    // 2 items — still too few
    stack.push_back({});
    BOOST_CHECK_EQUAL(GetUSDSOQWitnessTag(stack), 0x00);

    // 3 items, but tag slot [2] is empty
    stack.push_back({});
    BOOST_CHECK_EQUAL(GetUSDSOQWitnessTag(stack), 0x00);

    // MINT tag at index 2
    stack[2] = {0x01};
    BOOST_CHECK_EQUAL(GetUSDSOQWitnessTag(stack), 0x01);

    // BURN tag
    stack[2] = {0x02};
    BOOST_CHECK_EQUAL(GetUSDSOQWitnessTag(stack), 0x02);

    // FREEZE tag
    stack[2] = {0x03};
    BOOST_CHECK_EQUAL(GetUSDSOQWitnessTag(stack), 0x03);

    // ROTATE tag
    stack[2] = {0x04};
    BOOST_CHECK_EQUAL(GetUSDSOQWitnessTag(stack), 0x04);
}

BOOST_AUTO_TEST_CASE(witness_sig_extraction)
{
    // Test ExtractUSDSOQWitnessSignatures
    // Layout: [payout_sig(2421B)][payout_pk(1313B)][tag(1B)][payload(32B)][sig0..N(2420B)][authority_set]
    // Minimum 6 items required.

    std::vector<std::vector<uint8_t>> stack;

    // Too few items (need at least 6)
    stack.push_back(std::vector<uint8_t>(2421, 0x00));     // [0] payout_sig
    stack.push_back(std::vector<uint8_t>(1313, 0x00));     // [1] payout_pk
    stack.push_back({0x01});                                // [2] tag (MINT)
    stack.push_back(std::vector<uint8_t>(32, 0xAA));       // [3] payload
    stack.push_back(FakeSignature(0xBB));                   // [4] sig0
    // Only 5 items — missing authority_set → too few
    auto sigs = ExtractUSDSOQWitnessSignatures(stack);
    BOOST_CHECK(sigs.empty());

    // Add authority_set → now 6 items (minimum)
    stack.push_back(std::vector<uint8_t>(100, 0xCC));      // [5] authority_set
    sigs = ExtractUSDSOQWitnessSignatures(stack);
    BOOST_CHECK_EQUAL(sigs.size(), 1u);
    BOOST_CHECK_EQUAL(sigs[0].size(), DILITHIUM_SIG_SIZE);

    // Add second signature → 7 items
    // Insert before authority_set (index 5)
    stack.insert(stack.begin() + 5, FakeSignature(0xDD));  // [5] sig1, [6] authority_set
    sigs = ExtractUSDSOQWitnessSignatures(stack);
    BOOST_CHECK_EQUAL(sigs.size(), 2u);
}

BOOST_AUTO_TEST_CASE(witness_sig_extraction_non_sig_items_ignored)
{
    // Items between payload and authority_set that are NOT 2420 bytes
    // should be silently skipped
    std::vector<std::vector<uint8_t>> stack;
    stack.push_back(std::vector<uint8_t>(2421, 0x00));     // [0] payout_sig
    stack.push_back(std::vector<uint8_t>(1313, 0x00));     // [1] payout_pk
    stack.push_back({0x01});                                // [2] tag
    stack.push_back(std::vector<uint8_t>(32, 0xAA));       // [3] payload
    stack.push_back(std::vector<uint8_t>(100, 0xBB));      // [4] NOT a sig (wrong size)
    stack.push_back(FakeSignature(0xCC));                   // [5] valid sig size
    stack.push_back(std::vector<uint8_t>(200, 0xDD));      // [6] authority_set

    auto sigs = ExtractUSDSOQWitnessSignatures(stack);
    BOOST_CHECK_EQUAL(sigs.size(), 1u);  // Only the 2420-byte item
}

// =========================================================================
// 11. AUTHORITY KEY HASH COMPUTATION
// =========================================================================

BOOST_AUTO_TEST_CASE(compute_authority_key_hash)
{
    DilithiumKeypair k0, k1, k2;

    // Compute hash of keys
    std::vector<std::vector<uint8_t>> keys = {k0.pk, k1.pk, k2.pk};
    uint256 hash = ComputeAuthorityKeyHash(keys);

    // Hash should be non-zero
    BOOST_CHECK(!hash.IsNull());

    // Same keys in same order → same hash (deterministic)
    uint256 hash2 = ComputeAuthorityKeyHash(keys);
    BOOST_CHECK(hash == hash2);

    // Different key order → different hash
    std::vector<std::vector<uint8_t>> reorderedKeys = {k1.pk, k0.pk, k2.pk};
    uint256 hash3 = ComputeAuthorityKeyHash(reorderedKeys);
    BOOST_CHECK(hash != hash3);

    // Different key set → different hash
    DilithiumKeypair k3;
    std::vector<std::vector<uint8_t>> otherKeys = {k0.pk, k1.pk, k3.pk};
    uint256 hash4 = ComputeAuthorityKeyHash(otherKeys);
    BOOST_CHECK(hash != hash4);
}

// =========================================================================
// 12. AUTHORITY SCRIPT CONSTRUCTION
// =========================================================================

BOOST_AUTO_TEST_CASE(authority_script_format)
{
    DilithiumKeypair k0, k1, k2;
    std::vector<std::vector<uint8_t>> keys = {k0.pk, k1.pk, k2.pk};

    CScript script = MakeAuthorityScript(keys);

    // OP_5 <32-byte hash> = 1 + 1 + 32 = 34 bytes
    BOOST_CHECK_EQUAL(script.size(), 34u);
    BOOST_CHECK_EQUAL(script[0], OP_5);
    BOOST_CHECK_EQUAL(script[1], 32);  // push 32 bytes
}

// =========================================================================
// 13. BIP143 SIGHASH COMPUTATION
// =========================================================================

BOOST_AUTO_TEST_CASE(sighash_deterministic)
{
    // Build a simple TX with an authority input and output
    CMutableTransaction mtx;
    mtx.nVersion = 2;

    // Authority input
    COutPoint prevOut(uint256S("abcd1234abcd1234abcd1234abcd1234"
                               "abcd1234abcd1234abcd1234abcd1234"), 0);
    mtx.vin.push_back(CTxIn(prevOut, CScript(), 0xFFFFFFFF));

    // Authority output
    DilithiumKeypair k0, k1, k2;
    CScript authScript = MakeAuthorityScript({k0.pk, k1.pk, k2.pk});
    mtx.vout.push_back(CTxOut(CAmount(0), authScript));

    CTransaction tx(mtx);
    PrecomputedTransactionData txdata(tx);

    uint256 sighash = SignatureHash(
        authScript, tx, 0, SIGHASH_ALL,
        CAmount(0), SIGVERSION_WITNESS_V0, &txdata);

    // Sighash should be non-zero
    BOOST_CHECK(!sighash.IsNull());

    // Same TX → same sighash (deterministic)
    uint256 sighash2 = SignatureHash(
        authScript, tx, 0, SIGHASH_ALL,
        CAmount(0), SIGVERSION_WITNESS_V0, &txdata);
    BOOST_CHECK(sighash == sighash2);
}

BOOST_AUTO_TEST_CASE(sighash_changes_with_outputs)
{
    DilithiumKeypair k0, k1, k2;
    CScript authScript = MakeAuthorityScript({k0.pk, k1.pk, k2.pk});

    // TX #1: one output
    CMutableTransaction mtx1;
    mtx1.nVersion = 2;
    COutPoint prevOut(uint256S("abcd1234abcd1234abcd1234abcd1234"
                               "abcd1234abcd1234abcd1234abcd1234"), 0);
    mtx1.vin.push_back(CTxIn(prevOut, CScript(), 0xFFFFFFFF));
    mtx1.vout.push_back(CTxOut(CAmount(0), authScript));

    // TX #2: same input, different output amount
    CMutableTransaction mtx2 = mtx1;
    CScript destScript;
    destScript << OP_RETURN;
    mtx2.vout.push_back(CTxOut(CAmount(1000), destScript));

    CTransaction tx1(mtx1), tx2(mtx2);
    PrecomputedTransactionData td1(tx1), td2(tx2);

    uint256 sh1 = SignatureHash(authScript, tx1, 0, SIGHASH_ALL,
                                CAmount(0), SIGVERSION_WITNESS_V0, &td1);
    uint256 sh2 = SignatureHash(authScript, tx2, 0, SIGHASH_ALL,
                                CAmount(0), SIGVERSION_WITNESS_V0, &td2);

    // Different outputs → different sighash (SIGHASH_ALL covers all outputs)
    BOOST_CHECK(sh1 != sh2);
}

// =========================================================================
// 14. END-TO-END: SIGN + VERIFY PIPELINE
// =========================================================================

BOOST_AUTO_TEST_CASE(e2e_sign_verify_pipeline)
{
    // This test simulates the full usdsoqsigntx → ConnectBlock pipeline:
    // 1. Generate 3 keypairs
    // 2. Initialize authority (2-of-3)
    // 3. Build a mint TX with authority input/output
    // 4. Compute BIP143 sighash
    // 5. Sign with 2 keys
    // 6. Verify M-of-N
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    // Build the TX
    CMutableTransaction mtx;
    mtx.nVersion = 2;

    // Authority input (spending a prior authority UTXO)
    COutPoint authPrevOut(uint256S("1111111111111111111111111111111111111111111111111111111111111111"), 0);
    mtx.vin.push_back(CTxIn(authPrevOut, CScript(), 0xFFFFFFFF));

    // Authority output (continues the chain)
    CScript authScript = MakeAuthorityScript({k0.pk, k1.pk, k2.pk});
    mtx.vout.push_back(CTxOut(CAmount(0), authScript));

    // USDSOQ mint output
    CScript mintDest;
    mintDest << OP_DUP << OP_HASH160
             << std::vector<unsigned char>(20, 0xBE)
             << OP_EQUALVERIFY << OP_CHECKSIG;
    CTxOut mintOut(CAmount(100000), mintDest, VISIBILITY_TRANSPARENT, ASSET_TYPE_USDSOQ);
    mtx.vout.push_back(mintOut);

    CTransaction tx(mtx);
    PrecomputedTransactionData txdata(tx);

    // Compute BIP143 sighash for authority input (index 0)
    uint256 sighash = SignatureHash(
        authScript, tx, 0, SIGHASH_ALL,
        CAmount(0), SIGVERSION_WITNESS_V0, &txdata);

    std::vector<uint8_t> sighashBytes(sighash.begin(), sighash.end());

    // Sign with keys 0 and 2 (2-of-3)
    auto sig0 = DilithiumSign(sighashBytes, k0.sk);
    auto sig2 = DilithiumSign(sighashBytes, k2.sk);

    // Verify — this is what ConnectBlock calls
    BOOST_CHECK(auth.VerifyAuthoritySignatures(sighashBytes, {sig0, sig2}));
}

BOOST_AUTO_TEST_CASE(e2e_sign_verify_wrong_sighash_rejected)
{
    // Same as above but verify against a tampered TX (different amount)
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    // Build original TX
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    COutPoint authPrevOut(uint256S("2222222222222222222222222222222222222222222222222222222222222222"), 0);
    mtx.vin.push_back(CTxIn(authPrevOut, CScript(), 0xFFFFFFFF));

    CScript authScript = MakeAuthorityScript({k0.pk, k1.pk, k2.pk});
    mtx.vout.push_back(CTxOut(CAmount(0), authScript));

    CScript mintDest;
    mintDest << OP_RETURN;
    mtx.vout.push_back(CTxOut(CAmount(100000), mintDest, VISIBILITY_TRANSPARENT, ASSET_TYPE_USDSOQ));

    CTransaction txOriginal(mtx);
    PrecomputedTransactionData tddOriginal(txOriginal);

    // Compute sighash and sign
    uint256 originalSighash = SignatureHash(
        authScript, txOriginal, 0, SIGHASH_ALL,
        CAmount(0), SIGVERSION_WITNESS_V0, &tddOriginal);

    std::vector<uint8_t> originalBytes(originalSighash.begin(), originalSighash.end());
    auto sig0 = DilithiumSign(originalBytes, k0.sk);
    auto sig1 = DilithiumSign(originalBytes, k1.sk);

    // Tamper: change mint amount from 100000 to 999999
    mtx.vout[1].nValue = 999999;
    CTransaction txTampered(mtx);
    PrecomputedTransactionData tddTampered(txTampered);

    uint256 tamperedSighash = SignatureHash(
        authScript, txTampered, 0, SIGHASH_ALL,
        CAmount(0), SIGVERSION_WITNESS_V0, &tddTampered);

    std::vector<uint8_t> tamperedBytes(tamperedSighash.begin(), tamperedSighash.end());

    // Sigs were over the original sighash, not the tampered one
    BOOST_CHECK(originalSighash != tamperedSighash);
    BOOST_CHECK(!auth.VerifyAuthoritySignatures(tamperedBytes, {sig0, sig1}));

    // But original verification still works
    BOOST_CHECK(auth.VerifyAuthoritySignatures(originalBytes, {sig0, sig1}));
}

// =========================================================================
// 15. AUTHORITY KEY SET ROTATION
// =========================================================================

BOOST_AUTO_TEST_CASE(rotate_keys_valid)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    // Rotate to a new set of keys
    DilithiumKeypair k3, k4, k5;
    BOOST_CHECK(auth.RotateKeys({k3.pk, k4.pk, k5.pk}, 2));
    BOOST_CHECK_EQUAL(auth.GetKeyCount(), 3u);
    BOOST_CHECK_EQUAL(auth.GetThreshold(), 2u);

    // Old keys no longer verify
    auto msg = TestMessage();
    auto sig0 = DilithiumSign(msg, k0.sk);
    auto sig1 = DilithiumSign(msg, k1.sk);
    BOOST_CHECK(!auth.VerifyAuthoritySignatures(msg, {sig0, sig1}));

    // New keys verify
    auto sig3 = DilithiumSign(msg, k3.sk);
    auto sig4 = DilithiumSign(msg, k4.sk);
    BOOST_CHECK(auth.VerifyAuthoritySignatures(msg, {sig3, sig4}));
}

BOOST_AUTO_TEST_CASE(rotate_keys_reject_bad_threshold)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    DilithiumKeypair k3, k4;
    // Threshold too low
    BOOST_CHECK(!auth.RotateKeys({k3.pk, k4.pk}, 1));
    // Threshold too high
    BOOST_CHECK(!auth.RotateKeys({k3.pk, k4.pk}, 5));
}

// =========================================================================
// 16. AUTHORITY SERIALIZATION ROUNDTRIP WITH REAL KEYS
// =========================================================================

BOOST_AUTO_TEST_CASE(authority_serialize_real_keys)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority original;
    original.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    // Serialize
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    // Deserialize
    CUSDSOQAuthority restored;
    ss >> restored;

    BOOST_CHECK(restored.IsInitialized());
    BOOST_CHECK_EQUAL(restored.GetThreshold(), 2u);
    BOOST_CHECK_EQUAL(restored.GetKeyCount(), 3u);

    // Restored authority should still verify valid signatures
    auto msg = TestMessage();
    auto sig0 = DilithiumSign(msg, k0.sk);
    auto sig1 = DilithiumSign(msg, k1.sk);
    BOOST_CHECK(restored.VerifyAuthoritySignatures(msg, {sig0, sig1}));
}

// =========================================================================
// 17. MORE SIGNATURES THAN KEYS REJECTED
// =========================================================================

BOOST_AUTO_TEST_CASE(reject_more_sigs_than_keys)
{
    DilithiumKeypair k0, k1, k2;
    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    auto msg = TestMessage();

    // 4 sigs but only 3 keys — rejected by pre-check
    auto sig0 = DilithiumSign(msg, k0.sk);
    auto sig1 = DilithiumSign(msg, k1.sk);
    auto sig2 = DilithiumSign(msg, k2.sk);
    auto sigExtra = DilithiumSign(msg, k0.sk);  // duplicate

    BOOST_CHECK(!auth.VerifyAuthoritySignatures(msg, {sig0, sig1, sig2, sigExtra}));
}

// =========================================================================
// 18. CROSS-KEY VERIFICATION — SIGNATURES FROM NON-AUTHORITY KEYS
// =========================================================================

BOOST_AUTO_TEST_CASE(reject_sigs_from_non_authority_keys)
{
    DilithiumKeypair k0, k1, k2;  // Authority keys
    DilithiumKeypair attacker0, attacker1;  // NOT in authority set

    CUSDSOQAuthority auth;
    auth.Initialize({k0.pk, k1.pk, k2.pk}, 2);

    auto msg = TestMessage();

    // Attacker signs with their own keys
    auto aSig0 = DilithiumSign(msg, attacker0.sk);
    auto aSig1 = DilithiumSign(msg, attacker1.sk);

    // These are valid Dilithium signatures, but from the WRONG keys
    BOOST_CHECK(!auth.VerifyAuthoritySignatures(msg, {aSig0, aSig1}));
}

// =========================================================================
// 19. SUPPLY COUNTER: UNDO MINT / UNDO BURN (C1/C2 FIX)
// =========================================================================

BOOST_AUTO_TEST_CASE(supply_mint_undo_roundtrip)
{
    CUSDSOQSupply supply;

    // Mint 1000 USDSOQ
    BOOST_CHECK(supply.Mint(1000));
    BOOST_CHECK_EQUAL(supply.TotalMinted(), 1000);
    BOOST_CHECK_EQUAL(supply.Outstanding(), 1000);

    // Undo the mint (reorg)
    BOOST_CHECK(supply.UndoMint(1000));
    BOOST_CHECK_EQUAL(supply.TotalMinted(), 0);
    BOOST_CHECK_EQUAL(supply.Outstanding(), 0);
}

BOOST_AUTO_TEST_CASE(supply_burn_undo_roundtrip)
{
    CUSDSOQSupply supply;

    // Mint then burn
    BOOST_CHECK(supply.Mint(1000));
    BOOST_CHECK(supply.Burn(300));
    BOOST_CHECK_EQUAL(supply.TotalMinted(), 1000);
    BOOST_CHECK_EQUAL(supply.TotalBurned(), 300);
    BOOST_CHECK_EQUAL(supply.Outstanding(), 700);

    // Undo the burn (reorg)
    BOOST_CHECK(supply.UndoBurn(300));
    BOOST_CHECK_EQUAL(supply.TotalBurned(), 0);
    BOOST_CHECK_EQUAL(supply.Outstanding(), 1000);
}

BOOST_AUTO_TEST_CASE(supply_undo_mint_rejects_excess)
{
    CUSDSOQSupply supply;

    // Mint 500
    BOOST_CHECK(supply.Mint(500));

    // Try to undo 600 — more than was minted
    BOOST_CHECK(!supply.UndoMint(600));

    // Original state unchanged
    BOOST_CHECK_EQUAL(supply.TotalMinted(), 500);
}

BOOST_AUTO_TEST_CASE(supply_undo_burn_rejects_excess)
{
    CUSDSOQSupply supply;

    // Mint 500, burn 200
    BOOST_CHECK(supply.Mint(500));
    BOOST_CHECK(supply.Burn(200));

    // Try to undo 300 burn — more than was burned
    BOOST_CHECK(!supply.UndoBurn(300));

    // Original state unchanged
    BOOST_CHECK_EQUAL(supply.TotalBurned(), 200);
}

BOOST_AUTO_TEST_CASE(supply_undo_mint_respects_outstanding_invariant)
{
    CUSDSOQSupply supply;

    // Mint 500, burn 400 → outstanding 100
    BOOST_CHECK(supply.Mint(500));
    BOOST_CHECK(supply.Burn(400));

    // Try to undo 200 of the mint — would make minted=300, burned=400
    // which violates minted >= burned
    BOOST_CHECK(!supply.UndoMint(200));

    // State unchanged
    BOOST_CHECK_EQUAL(supply.TotalMinted(), 500);
    BOOST_CHECK_EQUAL(supply.TotalBurned(), 400);
}

BOOST_AUTO_TEST_CASE(supply_undo_rejects_zero_amount)
{
    CUSDSOQSupply supply;
    BOOST_CHECK(supply.Mint(1000));
    BOOST_CHECK(supply.Burn(500));

    // Zero amounts rejected
    BOOST_CHECK(!supply.UndoMint(0));
    BOOST_CHECK(!supply.UndoBurn(0));

    // Negative amounts rejected (CAmount is int64_t)
    BOOST_CHECK(!supply.UndoMint(-100));
    BOOST_CHECK(!supply.UndoBurn(-100));
}

BOOST_AUTO_TEST_CASE(supply_full_reorg_scenario)
{
    // Simulates a full ConnectBlock → DisconnectBlock cycle
    CUSDSOQSupply supply;

    // Block 100: authority mints 10000 USDSOQ
    BOOST_CHECK(supply.Mint(10000));
    BOOST_CHECK_EQUAL(supply.Outstanding(), 10000);

    // Block 101: user burns 2000 USDSOQ
    BOOST_CHECK(supply.Burn(2000));
    BOOST_CHECK_EQUAL(supply.Outstanding(), 8000);

    // Block 102: another mint of 5000
    BOOST_CHECK(supply.Mint(5000));
    BOOST_CHECK_EQUAL(supply.Outstanding(), 13000);

    // REORG: disconnect block 102 (undo mint of 5000)
    BOOST_CHECK(supply.UndoMint(5000));
    BOOST_CHECK_EQUAL(supply.Outstanding(), 8000);

    // REORG: disconnect block 101 (undo burn of 2000)
    BOOST_CHECK(supply.UndoBurn(2000));
    BOOST_CHECK_EQUAL(supply.Outstanding(), 10000);

    // REORG: disconnect block 100 (undo mint of 10000)
    BOOST_CHECK(supply.UndoMint(10000));
    BOOST_CHECK_EQUAL(supply.Outstanding(), 0);
    BOOST_CHECK_EQUAL(supply.TotalMinted(), 0);
    BOOST_CHECK_EQUAL(supply.TotalBurned(), 0);

    // Supply invariant still holds
    BOOST_CHECK(supply.CheckInvariant());
}

BOOST_AUTO_TEST_SUITE_END()
