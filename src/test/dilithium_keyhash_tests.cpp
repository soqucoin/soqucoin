// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// dilithium_keyhash_tests.cpp — Test vectors for OP_CHECKDILITHIUMKEYHASH (0xb6)
// 8 test vectors covering: NOP7 fallback, stack underflow, keyhash size,
// pubkey size, keyhash mismatch, valid round-trip, invalid sig, and
// opcode/flag regression checks.

#include "hash.h"
#include "key.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_bitcoin.h"
#include "crypto/sha256.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(dilithium_keyhash_tests, BasicTestingSetup)

// =========================================================================
// Helpers
// =========================================================================

static CMutableTransaction MakeSimpleTx()
{
    CMutableTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    CTxIn in;
    in.nSequence = 0xffffffff;
    tx.vin.push_back(in);
    CTxOut out;
    out.nValue = 50 * COIN;
    out.scriptPubKey = CScript() << OP_RETURN;
    tx.vout.push_back(out);
    return tx;
}

// Compute SHA256(pubkey) for a raw 1312-byte Dilithium pubkey
static std::vector<unsigned char> ComputeKeyHash(const std::vector<unsigned char>& pubkeyBytes)
{
    unsigned char hash[32];
    CSHA256().Write(pubkeyBytes.data(), pubkeyBytes.size()).Finalize(hash);
    return std::vector<unsigned char>(hash, hash + 32);
}

// =========================================================================
// Test 1: Without SCRIPT_VERIFY_DILITHIUM_KEYHASH flag → NOP7 (soft-fork safe)
// =========================================================================

BOOST_AUTO_TEST_CASE(keyhash_without_flag_is_nop)
{
    // When SCRIPT_VERIFY_DILITHIUM_KEYHASH is NOT set, OP_NOP7 must behave
    // as a NOP and not touch the stack. This is critical for soft-fork safety:
    // pre-activation nodes must accept blocks containing OP_NOP7 without error.
    unsigned int flags = 0; // no keyhash flag
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    CScript script;
    script << OP_TRUE << OP_NOP7; // OP_NOP7 = OP_CHECKDILITHIUMKEYHASH

    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK_MESSAGE(ok, "Without DILITHIUM_KEYHASH flag, OP_NOP7 must be a NOP");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
}

// =========================================================================
// Test 2: Empty stack → INVALID_STACK_OPERATION
// =========================================================================

BOOST_AUTO_TEST_CASE(keyhash_empty_stack_fails)
{
    // OP_CHECKDILITHIUMKEYHASH requires 3 items on the stack (keyhash, sig, pubkey).
    // With an empty stack, it must fail with SCRIPT_ERR_INVALID_STACK_OPERATION.
    unsigned int flags = SCRIPT_VERIFY_DILITHIUM_KEYHASH;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    CScript script;
    script << OP_CHECKDILITHIUMKEYHASH;

    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK_MESSAGE(!ok, "Empty stack must fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// =========================================================================
// Test 3: Wrong keyhash size (not 32 bytes) → CHECKDILITHIUMKEYHASH error
// =========================================================================

BOOST_AUTO_TEST_CASE(keyhash_wrong_hash_size_fails)
{
    // The keyhash must be exactly 32 bytes (SHA256 output). A 16-byte value
    // must be rejected with SCRIPT_ERR_CHECKDILITHIUMKEYHASH.
    unsigned int flags = SCRIPT_VERIFY_DILITHIUM_KEYHASH;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    std::vector<unsigned char> badHash(16, 0xaa); // wrong size
    std::vector<unsigned char> dummySig(2420, 0xbb);
    std::vector<unsigned char> dummyPubKey(1312, 0xcc);

    // Pre-load stack: sig (bottom), pubkey, keyhash (top)
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(dummySig);
    stack.push_back(dummyPubKey);
    stack.push_back(badHash);

    CScript script;
    script << OP_CHECKDILITHIUMKEYHASH;

    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK_MESSAGE(!ok, "Keyhash of wrong size (16 bytes) must fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
}

// =========================================================================
// Test 4: Wrong pubkey size (not 1312/1313 bytes) → CHECKDILITHIUMKEYHASH error
// =========================================================================

BOOST_AUTO_TEST_CASE(keyhash_wrong_pubkey_size_fails)
{
    // The pubkey must be 1312 bytes (raw ML-DSA-44) or 1313 bytes (0x00 prefix).
    // A 64-byte pubkey (like an ECDSA key) must be rejected.
    unsigned int flags = SCRIPT_VERIFY_DILITHIUM_KEYHASH;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    std::vector<unsigned char> validHash(32, 0xaa);
    std::vector<unsigned char> dummySig(2420, 0xbb);
    std::vector<unsigned char> badPubKey(64, 0xcc); // ECDSA-sized

    // Pre-load stack: sig (bottom), pubkey, keyhash (top)
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(dummySig);
    stack.push_back(badPubKey);
    stack.push_back(validHash);

    CScript script;
    script << OP_CHECKDILITHIUMKEYHASH;

    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK_MESSAGE(!ok, "Pubkey of wrong size (64 bytes, ECDSA-like) must fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
}

// =========================================================================
// Test 5: Keyhash mismatch (SHA256(pubkey) != provided keyhash)
// =========================================================================

BOOST_AUTO_TEST_CASE(keyhash_mismatch_fails)
{
    // Even with a correctly-sized pubkey and keyhash, if the keyhash does NOT
    // match SHA256(pubkey), the opcode must fail. This prevents key substitution.
    unsigned int flags = SCRIPT_VERIFY_DILITHIUM_KEYHASH;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    // Use a dummy 1312-byte pubkey
    std::vector<unsigned char> dummyPubKey(1312, 0x42);
    // Compute the real keyhash, then flip a byte to create a mismatch
    std::vector<unsigned char> correctHash = ComputeKeyHash(dummyPubKey);
    std::vector<unsigned char> wrongHash = correctHash;
    wrongHash[0] ^= 0xff; // flip first byte

    std::vector<unsigned char> dummySig(2420, 0xbb);

    // Pre-load stack: sig (bottom), pubkey, keyhash (top)
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(dummySig);
    stack.push_back(dummyPubKey);
    stack.push_back(wrongHash);

    CScript script;
    script << OP_CHECKDILITHIUMKEYHASH;

    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK_MESSAGE(!ok, "Keyhash mismatch (flipped byte) must fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
}

// =========================================================================
// Test 6: Valid keyhash + valid Dilithium sig → passes (round-trip)
// =========================================================================

BOOST_AUTO_TEST_CASE(keyhash_valid_roundtrip)
{
    // Full end-to-end test: generate a real Dilithium key, compute the keyhash,
    // sign a transaction, and verify that OP_CHECKDILITHIUMKEYHASH succeeds.
    //
    // This is the golden-path test. If this fails, the opcode is broken.
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());
    BOOST_REQUIRE_EQUAL(pubkey.size(), 1312u);

    // Get raw pubkey bytes and compute SHA256 keyhash
    std::vector<unsigned char> pubkeyBytes(pubkey.begin(), pubkey.end());
    std::vector<unsigned char> keyhash = ComputeKeyHash(pubkeyBytes);
    BOOST_REQUIRE_EQUAL(keyhash.size(), 32u);

    // Build a spending transaction
    CMutableTransaction tx = MakeSimpleTx();

    // The corrected handler reads:
    //   stacktop(-1) = keyhash (committed by script, on top)
    //   stacktop(-2) = pubkey  (from witness)
    //   stacktop(-3) = sig     (from witness)
    // and pops all 3 on success (CSFS-VERIFY style).
    //
    // For this bare-EvalScript test we pre-load the stack and execute just the opcode.

    // Sign the transaction — scriptCode matches the real v6 witnessScript pattern:
    //   <keyhash> OP_CHECKDILITHIUMKEYHASH OP_1
    // but for bare-EvalScript we pre-load the keyhash and omit its push from
    // scriptCode. The opcode pops all 3, then OP_1 pushes truthy for EvalScript.
    CScript scriptCode;
    scriptCode << OP_CHECKDILITHIUMKEYHASH << OP_1;
    uint256 sighash = SignatureHash(scriptCode, CTransaction(tx), 0, SIGHASH_ALL, 0, SIGVERSION_BASE, nullptr);

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    // Append SIGHASH_ALL byte (CheckSig expects it)
    sig.push_back((unsigned char)SIGHASH_ALL);

    // Pre-load stack: sig (bottom), pubkey, keyhash (top)
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(sig);
    stack.push_back(pubkeyBytes);
    stack.push_back(keyhash);

    unsigned int flags = SCRIPT_VERIFY_DILITHIUM_KEYHASH;
    ScriptError serror = SCRIPT_ERR_OK;
    MutableTransactionSignatureChecker checker(&tx, 0, 0);

    bool ok = EvalScript(stack, scriptCode, flags, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK_MESSAGE(ok, "Valid keyhash + valid sig must pass: " + std::string(ScriptErrorString(serror)));

    // After success: all 3 items popped, OP_1 pushed truthy value
    BOOST_CHECK_EQUAL(stack.size(), 1u);
}

// =========================================================================
// Test 7: Valid keyhash + invalid sig → CHECKDILITHIUMKEYHASH error
// =========================================================================

BOOST_AUTO_TEST_CASE(keyhash_invalid_sig_fails)
{
    // The keyhash matches SHA256(pubkey), but the signature is garbage.
    // Step 1 (keyhash check) passes, but Step 2 (sig verify) must fail.
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    std::vector<unsigned char> pubkeyBytes(pubkey.begin(), pubkey.end());
    std::vector<unsigned char> keyhash = ComputeKeyHash(pubkeyBytes);

    // Create a garbage signature (correct size but wrong content)
    std::vector<unsigned char> garbageSig(2421, 0xde);
    garbageSig[2420] = SIGHASH_ALL; // valid hashtype byte

    CMutableTransaction tx = MakeSimpleTx();

    // Pre-load stack: sig (bottom), pubkey, keyhash (top)
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(garbageSig);
    stack.push_back(pubkeyBytes);
    stack.push_back(keyhash);

    CScript script;
    script << OP_CHECKDILITHIUMKEYHASH;

    unsigned int flags = SCRIPT_VERIFY_DILITHIUM_KEYHASH;
    ScriptError serror = SCRIPT_ERR_OK;
    MutableTransactionSignatureChecker checker(&tx, 0, 0);

    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK_MESSAGE(!ok, "Valid keyhash + garbage sig must fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CHECKDILITHIUMKEYHASH);
}

// =========================================================================
// Test 8: Opcode constant and flag regression
// =========================================================================

BOOST_AUTO_TEST_CASE(keyhash_opcode_and_flag_constants)
{
    // Verify the opcode byte, flag bit, and flag non-collision
    BOOST_CHECK_EQUAL((int)OP_CHECKDILITHIUMKEYHASH, 0xb6);
    BOOST_CHECK_EQUAL((int)OP_NOP7, 0xb6);

    // SCRIPT_VERIFY_DILITHIUM_KEYHASH = (1U << 25)
    BOOST_CHECK_EQUAL(SCRIPT_VERIFY_DILITHIUM_KEYHASH, (1U << 25));

    // Must not collide with any existing flag
    BOOST_CHECK((SCRIPT_VERIFY_DILITHIUM_KEYHASH & SCRIPT_VERIFY_CTV) == 0);
    BOOST_CHECK((SCRIPT_VERIFY_DILITHIUM_KEYHASH & SCRIPT_VERIFY_APO) == 0);
    BOOST_CHECK((SCRIPT_VERIFY_DILITHIUM_KEYHASH & SCRIPT_VERIFY_CSFS) == 0);
    BOOST_CHECK((SCRIPT_VERIFY_DILITHIUM_KEYHASH & SCRIPT_VERIFY_SCRIPT_RESTORE) == 0);

    // GetOpName must return the correct string
    BOOST_CHECK_EQUAL(std::string(GetOpName(OP_CHECKDILITHIUMKEYHASH)),
                      std::string("OP_CHECKDILITHIUMKEYHASH"));

    // GetSigOpCount must count OP_CHECKDILITHIUMKEYHASH as 1 sigop
    CScript script;
    script << OP_CHECKDILITHIUMKEYHASH;
    BOOST_CHECK_EQUAL(script.GetSigOpCount(true), 1u);

    // Verify it counts alongside other sig ops
    CScript multiSigOp;
    multiSigOp << OP_CHECKSIG << OP_CHECKDILITHIUMKEYHASH << OP_CHECKSIGFROMSTACK;
    BOOST_CHECK_EQUAL(multiSigOp.GetSigOpCount(true), 3u);
}

BOOST_AUTO_TEST_SUITE_END()
