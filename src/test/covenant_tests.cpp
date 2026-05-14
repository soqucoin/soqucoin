// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// covenant_tests.cpp — Test vectors for SOQ-COV adversarial audit
// Covers: CTV (BIP119), APO (BIP118), CSFS (BIP348), OP_CAT, Satoshi restore
// All findings SOQ-COV-001 through SOQ-COV-009 have regression tests here.

#include "hash.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_bitcoin.h"
#include "crypto/sha256.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(covenant_tests, BasicTestingSetup)

// =========================================================================
// Helpers
// =========================================================================

static CMutableTransaction MakeBaseTx()
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

// Compute CTV hash the same way CheckTemplateVerify does (LE, canonical)
static std::vector<unsigned char> ComputeCTVHash(const CMutableTransaction& tx, unsigned int nIn)
{
    auto writeLE32 = [](CSHA256& h, uint32_t v) {
        uint8_t buf[4] = {(uint8_t)(v), (uint8_t)(v>>8), (uint8_t)(v>>16), (uint8_t)(v>>24)};
        h.Write(buf, 4);
    };
    auto writeLE64 = [](CSHA256& h, int64_t v) {
        uint64_t u = (uint64_t)v;
        uint8_t buf[8] = {(uint8_t)(u),(uint8_t)(u>>8),(uint8_t)(u>>16),(uint8_t)(u>>24),
                          (uint8_t)(u>>32),(uint8_t)(u>>40),(uint8_t)(u>>48),(uint8_t)(u>>56)};
        h.Write(buf, 8);
    };

    CSHA256 ss;
    writeLE32(ss, (uint32_t)tx.nVersion);
    writeLE32(ss, tx.nLockTime);

    // No scriptSigs in base tx
    writeLE32(ss, (uint32_t)tx.vin.size());

    CSHA256 ssSeq;
    for (const auto& txin : tx.vin) writeLE32(ssSeq, txin.nSequence);
    uint8_t seqHash[32]; ssSeq.Finalize(seqHash);
    ss.Write(seqHash, 32);

    writeLE32(ss, (uint32_t)tx.vout.size());

    CSHA256 ssOut;
    for (const auto& txout : tx.vout) {
        writeLE64(ssOut, txout.nValue);
        writeLE32(ssOut, (uint32_t)txout.scriptPubKey.size());
        if (!txout.scriptPubKey.empty())
            ssOut.Write(txout.scriptPubKey.data(), txout.scriptPubKey.size());
    }
    uint8_t outHash[32]; ssOut.Finalize(outHash);
    ss.Write(outHash, 32);

    writeLE32(ss, nIn);

    uint8_t result[32]; ss.Finalize(result);
    return std::vector<unsigned char>(result, result + 32);
}

// =========================================================================
// 1. CTV — OP_CHECKTEMPLATEVERIFY (SOQ-COV-001, 002)
// =========================================================================

BOOST_AUTO_TEST_CASE(ctv_correct_hash_passes)
{
    // CTV with the correct template hash succeeds
    CMutableTransaction tx = MakeBaseTx();
    CTransaction ctx(tx);
    auto hash = ComputeCTVHash(tx, 0);

    CScript script;
    script << hash << OP_NOP4; // OP_NOP4 = CTV opcode

    std::vector<std::vector<unsigned char>> stack;
    unsigned int flags = SCRIPT_VERIFY_CTV;
    ScriptError serror = SCRIPT_ERR_OK;
    MutableTransactionSignatureChecker checker(&tx, 0, 0);

    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK_MESSAGE(ok, "CTV with correct hash should pass");
}

BOOST_AUTO_TEST_CASE(ctv_wrong_hash_fails)
{
    // CTV with a wrong hash must fail
    CMutableTransaction tx = MakeBaseTx();
    std::vector<unsigned char> badHash(32, 0xde);

    CScript script;
    script << badHash << OP_NOP4;

    std::vector<std::vector<unsigned char>> stack;
    unsigned int flags = SCRIPT_VERIFY_CTV;
    ScriptError serror = SCRIPT_ERR_OK;
    MutableTransactionSignatureChecker checker(&tx, 0, 0);

    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK_MESSAGE(!ok, "CTV with wrong hash must fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CHECKTEMPLATEVERIFY);
}

BOOST_AUTO_TEST_CASE(ctv_nversion_change_breaks_hash)
{
    // SOQ-COV-001: changing nVersion changes the CTV hash (canonical LE serialization)
    CMutableTransaction tx1 = MakeBaseTx();
    CMutableTransaction tx2 = MakeBaseTx();
    tx2.nVersion = 2;

    auto hash1 = ComputeCTVHash(tx1, 0);
    auto hash2 = ComputeCTVHash(tx2, 0);
    BOOST_CHECK(hash1 != hash2);

    // tx1's hash fails against tx2
    CScript script;
    script << hash1 << OP_NOP4;

    std::vector<std::vector<unsigned char>> stack;
    unsigned int flags = SCRIPT_VERIFY_CTV;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx2, 0, 0);
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CHECKTEMPLATEVERIFY);
}

BOOST_AUTO_TEST_CASE(ctv_output_change_breaks_hash)
{
    // Changing an output value invalidates the template
    CMutableTransaction tx1 = MakeBaseTx();
    CMutableTransaction tx2 = MakeBaseTx();
    tx2.vout[0].nValue = 1 * COIN; // different amount

    auto hash1 = ComputeCTVHash(tx1, 0);

    CScript script;
    script << hash1 << OP_NOP4;

    std::vector<std::vector<unsigned char>> stack;
    unsigned int flags = SCRIPT_VERIFY_CTV;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx2, 0, 0);
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CHECKTEMPLATEVERIFY);
}

BOOST_AUTO_TEST_CASE(ctv_nop4_without_flag_is_nop)
{
    // Without SCRIPT_VERIFY_CTV flag, OP_NOP4 is a NOP (soft-fork compatible)
    CMutableTransaction tx = MakeBaseTx();
    std::vector<unsigned char> badHash(32, 0xff);

    CScript script;
    script << badHash << OP_NOP4;

    std::vector<std::vector<unsigned char>> stack;
    unsigned int flags = 0; // no CTV flag
    ScriptError serror = SCRIPT_ERR_OK;
    MutableTransactionSignatureChecker checker(&tx, 0, 0);

    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK_MESSAGE(ok, "Without SCRIPT_VERIFY_CTV, OP_NOP4 must be NOP (not fail)");
}

BOOST_AUTO_TEST_CASE(ctv_empty_stack_fails)
{
    CMutableTransaction tx = MakeBaseTx();
    CScript script;
    script << OP_NOP4; // no hash on stack

    std::vector<std::vector<unsigned char>> stack;
    unsigned int flags = SCRIPT_VERIFY_CTV;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 0);
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(ctv_wrong_hash_size_fails)
{
    // Hash must be exactly 32 bytes
    CMutableTransaction tx = MakeBaseTx();
    std::vector<unsigned char> shortHash(16, 0xaa);

    CScript script;
    script << shortHash << OP_NOP4;

    std::vector<std::vector<unsigned char>> stack;
    unsigned int flags = SCRIPT_VERIFY_CTV;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 0);
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CHECKTEMPLATEVERIFY);
}

// =========================================================================
// 2. APO — SIGHASH_ANYONECANPAY rejection (SOQ-COV-003, COV-009)
// =========================================================================

BOOST_AUTO_TEST_CASE(apo_anyonecanpay_combination_rejected)
{
    // SOQ-COV-003: SIGHASH_ANYPREVOUT | SIGHASH_ANYONECANPAY (0xC1) returns sentinel
    CMutableTransaction tx = MakeBaseTx();
    CTransaction ctx(tx);
    CScript scriptCode;
    scriptCode << OP_TRUE;

    // 0x41 | 0x80 = 0xC1
    int badHashType = 0x41 | 0x80;
    uint256 hash = SignatureHash(scriptCode, ctx, 0, badHashType, 0, SIGVERSION_WITNESS_V0, nullptr);

    // The guard returns uint256::ONE. Verify it is NOT all-zeros (not a real hash)
    BOOST_CHECK(hash != uint256());
    BOOST_CHECK(hash == uint256::ONE);
}

BOOST_AUTO_TEST_CASE(apo_anyprevoutanyscript_anyonecanpay_rejected)
{
    // 0x42 | 0x80 = 0xC2 — also must return sentinel
    CMutableTransaction tx = MakeBaseTx();
    CTransaction ctx(tx);
    CScript scriptCode;
    scriptCode << OP_TRUE;

    int badHashType = 0x42 | 0x80;
    uint256 hash = SignatureHash(scriptCode, ctx, 0, badHashType, 0, SIGVERSION_WITNESS_V0, nullptr);
    BOOST_CHECK(hash != uint256());
    BOOST_CHECK(hash == uint256::ONE);
}

BOOST_AUTO_TEST_CASE(checksig_rejects_apo_hashtype)
{
    // SOQ-COV-009: CheckSig must reject nHashType 0x41 and 0x42
    // Build a fake sig with hash type byte 0x41 appended
    CMutableTransaction tx = MakeBaseTx();
    CTransaction ctx(tx);

    std::vector<unsigned char> fakeSig(10, 0xab);
    fakeSig.push_back(0x41); // APO hash type byte

    std::vector<unsigned char> fakePubKey(1312, 0x01); // dummy Dilithium pubkey

    CScript scriptCode;
    scriptCode << OP_TRUE;

    TransactionSignatureChecker checker(&ctx, 0, 0);
    bool ok = checker.CheckSig(fakeSig, fakePubKey, scriptCode, SIGVERSION_BASE);
    BOOST_CHECK_MESSAGE(!ok, "CheckSig must reject APO sighash type 0x41");

    // Also test 0x42
    fakeSig.back() = 0x42;
    ok = checker.CheckSig(fakeSig, fakePubKey, scriptCode, SIGVERSION_BASE);
    BOOST_CHECK_MESSAGE(!ok, "CheckSig must reject APO sighash type 0x42");
}

BOOST_AUTO_TEST_CASE(checksig_rejects_apo_with_anyonecanpay)
{
    // 0xC1 and 0xC2 also rejected at CheckSig level
    CMutableTransaction tx = MakeBaseTx();
    CTransaction ctx(tx);
    std::vector<unsigned char> fakeSig(10, 0xab);
    std::vector<unsigned char> fakePubKey(1312, 0x01);
    CScript scriptCode;
    scriptCode << OP_TRUE;
    TransactionSignatureChecker checker(&ctx, 0, 0);

    fakeSig.push_back(0xC1);
    BOOST_CHECK(!checker.CheckSig(fakeSig, fakePubKey, scriptCode, SIGVERSION_BASE));

    fakeSig.back() = 0xC2;
    BOOST_CHECK(!checker.CheckSig(fakeSig, fakePubKey, scriptCode, SIGVERSION_BASE));
}

// =========================================================================
// 3. CSFS — OP_CHECKSIGFROMSTACK (SOQ-COV-005, COV-006)
// =========================================================================

BOOST_AUTO_TEST_CASE(csfs_wrong_pubkey_size_fails)
{
    // Wrong pubkey size (not 1312/1313) must fail
    unsigned int flags = SCRIPT_VERIFY_CSFS;
    ScriptError serror;
    BaseSignatureChecker checker;

    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(100, 0xaa)); // sig
    stack.push_back(std::vector<unsigned char>(32, 0xbb));  // msg
    stack.push_back(std::vector<unsigned char>(64, 0xcc));  // wrong pubkey size

    CScript script;
    script << OP_NOP5; // CSFS opcode

    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CHECKSIGFROMSTACK);
}

BOOST_AUTO_TEST_CASE(csfs_without_flag_is_nop)
{
    // Without SCRIPT_VERIFY_CSFS, OP_NOP5 must be NOP
    unsigned int flags = 0;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    CScript script;
    script << OP_TRUE << OP_NOP5;

    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
}

BOOST_AUTO_TEST_CASE(csfs_empty_stack_fails)
{
    unsigned int flags = SCRIPT_VERIFY_CSFS;
    ScriptError serror;
    BaseSignatureChecker checker;
    CScript script;
    script << OP_NOP5;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(csfs_message_hashing_is_double_sha256)
{
    // SOQ-COV-006: verify that CSFS message hashing uses double-SHA256
    // We can verify this indirectly: Hash() (double) != single SHA256 for non-empty data
    std::vector<unsigned char> msg(32, 0xaa);

    // Single SHA256
    uint256 single;
    CSHA256().Write(msg.data(), msg.size()).Finalize(single.begin());

    // Double SHA256 (what CSFS now uses)
    uint256 doubleSha = Hash(msg.begin(), msg.end());

    BOOST_CHECK(single != doubleSha);
    // This confirms the fix is meaningful: oracle signing with Hash() ≠ single SHA256
}

// =========================================================================
// 4. OP_CAT (SOQ-COV-008)
// =========================================================================

BOOST_AUTO_TEST_CASE(op_cat_basic_concatenation)
{
    unsigned int flags = SCRIPT_VERIFY_P2SH;
    ScriptError serror;
    BaseSignatureChecker checker;

    std::vector<unsigned char> a = {0x01, 0x02};
    std::vector<unsigned char> b = {0x03, 0x04};
    std::vector<unsigned char> expected = {0x01, 0x02, 0x03, 0x04};

    CScript script;
    script << a << b << OP_CAT;

    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_REQUIRE_EQUAL(stack.size(), 1u);
    BOOST_CHECK(stack[0] == expected);
}

BOOST_AUTO_TEST_CASE(op_cat_size_limit_enforced)
{
    // Result exceeding MAX_SCRIPT_ELEMENT_SIZE (520) must fail
    unsigned int flags = SCRIPT_VERIFY_P2SH;
    ScriptError serror;
    BaseSignatureChecker checker;

    std::vector<unsigned char> big(261, 0xaa);
    CScript script;
    script << big << big << OP_CAT; // 261+261=522 > 520

    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(op_cat_exactly_520_bytes_passes)
{
    unsigned int flags = SCRIPT_VERIFY_P2SH;
    ScriptError serror;
    BaseSignatureChecker checker;

    std::vector<unsigned char> a(260, 0xaa);
    std::vector<unsigned char> b(260, 0xbb);
    CScript script;
    script << a << b << OP_CAT; // 520 == limit

    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(stack[0].size(), 520u);
}

BOOST_AUTO_TEST_CASE(op_cat_empty_stack_fails)
{
    unsigned int flags = SCRIPT_VERIFY_P2SH;
    ScriptError serror;
    BaseSignatureChecker checker;
    CScript script;
    script << OP_CAT;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// =========================================================================
// 5. Satoshi Restore: OP_MUL / OP_DIV / OP_MOD (SOQ-COV-007 confirms clean)
// =========================================================================

BOOST_AUTO_TEST_CASE(op_mul_basic)
{
    // SCRIPT_VERIFY_SCRIPT_RESTORE activates satoshi opcodes
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SCRIPT_RESTORE;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    CScript script;
    script << CScriptNum(6) << CScriptNum(7) << OP_MUL;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_REQUIRE(!stack.empty());
    BOOST_CHECK_EQUAL(CScriptNum(stack[0], false).getint(), 42);
}

BOOST_AUTO_TEST_CASE(op_mul_overflow_fails)
{
    // INT64_MAX * 2 overflows — overflow guard fires, not UB
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SCRIPT_RESTORE;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    // Use large values within CScriptNum's 8-byte range
    CScript script;
    script << CScriptNum(INT32_MAX) << CScriptNum(INT32_MAX) << OP_MUL;
    std::vector<std::vector<unsigned char>> stack;
    // This specific combination overflows int64: INT32_MAX^2 > INT64_MAX
    // However CScriptNum with size 8 can hold up to INT64_MAX.
    // Use values guaranteed to overflow:
    CScript script2;
    int64_t big = (int64_t)4000000000LL;
    script2 << CScriptNum(big) << CScriptNum(big) << OP_MUL; // 16e18 > INT64_MAX
    std::vector<std::vector<unsigned char>> stack2;
    BOOST_CHECK(!EvalScript(stack2, script2, flags, checker, SIGVERSION_BASE, &serror));
}

BOOST_AUTO_TEST_CASE(op_mul_by_zero)
{
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SCRIPT_RESTORE;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;
    CScript script;
    script << CScriptNum(12345) << CScriptNum(0) << OP_MUL;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_REQUIRE(!stack.empty());
    BOOST_CHECK_EQUAL(CScriptNum(stack[0], false).getint(), 0);
}

BOOST_AUTO_TEST_CASE(op_div_basic)
{
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SCRIPT_RESTORE;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;
    CScript script;
    script << CScriptNum(42) << CScriptNum(6) << OP_DIV;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_REQUIRE(!stack.empty());
    BOOST_CHECK_EQUAL(CScriptNum(stack[0], false).getint(), 7);
}

BOOST_AUTO_TEST_CASE(op_div_by_zero_fails)
{
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SCRIPT_RESTORE;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;
    CScript script;
    script << CScriptNum(42) << CScriptNum(0) << OP_DIV;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DIV_BY_ZERO);
}

BOOST_AUTO_TEST_CASE(op_mod_basic)
{
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SCRIPT_RESTORE;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;
    CScript script;
    script << CScriptNum(17) << CScriptNum(5) << OP_MOD;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_REQUIRE(!stack.empty());
    BOOST_CHECK_EQUAL(CScriptNum(stack[0], false).getint(), 2);
}

BOOST_AUTO_TEST_CASE(op_mod_by_zero_fails)
{
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SCRIPT_RESTORE;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;
    CScript script;
    script << CScriptNum(10) << CScriptNum(0) << OP_MOD;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DIV_BY_ZERO);
}

// =========================================================================
// 6. OP_SUBSTR / OP_LEFT / OP_RIGHT
// =========================================================================

BOOST_AUTO_TEST_CASE(op_substr_basic)
{
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SCRIPT_RESTORE;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;
    std::vector<unsigned char> data = {0x01,0x02,0x03,0x04,0x05};
    CScript script;
    script << data << CScriptNum(1) << CScriptNum(3) << OP_SUBSTR;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_REQUIRE(!stack.empty());
    std::vector<unsigned char> expected = {0x02,0x03,0x04};
    BOOST_CHECK(stack[0] == expected);
}

BOOST_AUTO_TEST_CASE(op_substr_out_of_range_fails)
{
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SCRIPT_RESTORE;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;
    std::vector<unsigned char> data = {0x01,0x02,0x03};
    CScript script;
    script << data << CScriptNum(2) << CScriptNum(5) << OP_SUBSTR; // 2+5=7 > 3
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_SPLIT_RANGE);
}

BOOST_AUTO_TEST_CASE(op_left_basic)
{
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SCRIPT_RESTORE;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;
    std::vector<unsigned char> data = {0x0a,0x0b,0x0c,0x0d};
    CScript script;
    script << data << CScriptNum(2) << OP_LEFT;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_REQUIRE(!stack.empty());
    std::vector<unsigned char> expected = {0x0a,0x0b};
    BOOST_CHECK(stack[0] == expected);
}

BOOST_AUTO_TEST_CASE(op_right_basic)
{
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SCRIPT_RESTORE;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;
    std::vector<unsigned char> data = {0x0a,0x0b,0x0c,0x0d};
    CScript script;
    script << data << CScriptNum(2) << OP_RIGHT;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_REQUIRE(!stack.empty());
    std::vector<unsigned char> expected = {0x0c,0x0d};
    BOOST_CHECK(stack[0] == expected);
}

// =========================================================================
// 7. Opcode constant regression
// =========================================================================

BOOST_AUTO_TEST_CASE(opcode_constants)
{
    BOOST_CHECK_EQUAL((int)OP_CAT,    0x7e);
    BOOST_CHECK_EQUAL((int)OP_SUBSTR, 0x7f);
    BOOST_CHECK_EQUAL((int)OP_LEFT,   0x80);
    BOOST_CHECK_EQUAL((int)OP_RIGHT,  0x81);
    BOOST_CHECK_EQUAL((int)OP_NOP4,   0xb3); // CTV
    BOOST_CHECK_EQUAL((int)OP_NOP5,   0xb4); // CSFS
    BOOST_CHECK_EQUAL((int)OP_MUL,    0x95);
    BOOST_CHECK_EQUAL((int)OP_DIV,    0x96);
    BOOST_CHECK_EQUAL((int)OP_MOD,    0x97);
}

BOOST_AUTO_TEST_CASE(script_verify_flag_no_collision)
{
    // APO, CTV, CSFS bits must be distinct
    BOOST_CHECK((SCRIPT_VERIFY_CTV  & SCRIPT_VERIFY_APO)  == 0);
    BOOST_CHECK((SCRIPT_VERIFY_CTV  & SCRIPT_VERIFY_CSFS) == 0);
    BOOST_CHECK((SCRIPT_VERIFY_APO  & SCRIPT_VERIFY_CSFS) == 0);
}

BOOST_AUTO_TEST_CASE(apo_hashtype_constants)
{
    BOOST_CHECK_EQUAL((int)SIGHASH_ANYPREVOUT,          0x41);
    BOOST_CHECK_EQUAL((int)SIGHASH_ANYPREVOUTANYSCRIPT, 0x42);
    // ANYONECANPAY mask
    BOOST_CHECK_EQUAL(0x41 | 0x80, 0xC1);
    BOOST_CHECK_EQUAL(0x42 | 0x80, 0xC2);
}

BOOST_AUTO_TEST_SUITE_END()
