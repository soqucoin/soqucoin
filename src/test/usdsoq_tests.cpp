// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-AUD2-002: USDSOQ Stablecoin Consensus Tests
// Phase 4: Refactored to remove nVisibility/nAssetType byte-level tests.
// Classification is now structural: v7 witness = USDSOQ, v4 witness = confidential.
// Covers: CTxOut predicates, supply counter, asset isolation, opcode dispatch,
//         BIP9 gating, compressor serialization.

#include "chainparams.h"
#include "compressor.h"
#include "consensus/usdsoq.h"
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "validation.h"
#include "versionbits.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(usdsoq_tests, BasicTestingSetup)

// =========================================================================
// Helpers: Phase 4 structural output construction
// =========================================================================

// Build a v7 witness scriptPubKey (USDSOQ classification)
static CScript MakeV7Script() {
    CScript s;
    s << OP_7 << std::vector<unsigned char>(32, 0xab);
    return s;
}

// Build a v4 witness scriptPubKey (confidential classification)
static CScript MakeV4Script() {
    CScript s;
    s << OP_4 << std::vector<unsigned char>(32, 0xab);
    return s;
}

// Build a v1 witness scriptPubKey (transparent native SOQ)
static CScript MakeV1Script() {
    CScript s;
    s << OP_1 << std::vector<unsigned char>(32, 0xcd);
    return s;
}

// Build a standard P2PKH scriptPubKey (transparent native SOQ)
static CScript MakeP2PKH() {
    CScript s;
    s << OP_DUP << OP_HASH160
      << std::vector<unsigned char>(20, 0xab)
      << OP_EQUALVERIFY << OP_CHECKSIG;
    return s;
}

// =========================================================================
// 1. CONSTANTS & DATA STRUCTURES
// =========================================================================

BOOST_AUTO_TEST_CASE(asset_type_constants)
{
    BOOST_CHECK_EQUAL(ASSET_TYPE_SOQ, 0x00);
    BOOST_CHECK_EQUAL(ASSET_TYPE_USDSOQ, 0x01);
    BOOST_CHECK_EQUAL(ASSET_SOQ, ASSET_TYPE_SOQ);
    BOOST_CHECK_EQUAL(ASSET_USDSOQ, ASSET_TYPE_USDSOQ);
    BOOST_CHECK_EQUAL(ASSET_TYPE_MAX, 0x01);
}

BOOST_AUTO_TEST_CASE(visibility_constants)
{
    BOOST_CHECK_EQUAL(VISIBILITY_TRANSPARENT, 0x00);
    BOOST_CHECK_EQUAL(VISIBILITY_CONFIDENTIAL, 0x01);
    BOOST_CHECK_EQUAL(VISIBILITY_FROZEN_MASK, 0x80);
    BOOST_CHECK_EQUAL(VISIBILITY_MAX, 0x01);

    // Frozen mask preserves base visibility mode
    BOOST_CHECK_EQUAL((VISIBILITY_FROZEN_MASK | VISIBILITY_TRANSPARENT) & ~VISIBILITY_FROZEN_MASK, VISIBILITY_TRANSPARENT);
    BOOST_CHECK_EQUAL((VISIBILITY_FROZEN_MASK | VISIBILITY_CONFIDENTIAL) & ~VISIBILITY_FROZEN_MASK, VISIBILITY_CONFIDENTIAL);
}

BOOST_AUTO_TEST_CASE(authority_limits)
{
    BOOST_CHECK_EQUAL(USDSOQ_MAX_AUTHORITY_KEYS, 15u);
    BOOST_CHECK_EQUAL(USDSOQ_MIN_THRESHOLD, 2u);
    BOOST_CHECK_EQUAL(DILITHIUM_PUBKEY_SIZE, 1312u);
    BOOST_CHECK_EQUAL(DILITHIUM_SIG_SIZE, 2420u);
}

// =========================================================================
// 2. CTxOut PREDICATE TESTS (Phase 4 — structural classification)
// =========================================================================

BOOST_AUTO_TEST_CASE(ctxout_default_fields)
{
    CTxOut out;
    out.SetNull();
    // Default CTxOut has no witness program → transparent native SOQ
    BOOST_CHECK(out.IsNativeSOQ());
    BOOST_CHECK(out.IsTransparent());
    BOOST_CHECK(!out.IsUSDSOQ());
    BOOST_CHECK(!out.IsConfidential());
}

BOOST_AUTO_TEST_CASE(ctxout_v7_is_usdsoq)
{
    // Phase 4: v7 witness scriptPubKey = USDSOQ
    CTxOut out(1000, MakeV7Script());
    BOOST_CHECK_EQUAL(out.nValue, 1000);
    BOOST_CHECK(out.IsUSDSOQ());
    BOOST_CHECK(!out.IsNativeSOQ());
    BOOST_CHECK(!out.IsConfidential());
}

BOOST_AUTO_TEST_CASE(ctxout_v4_is_confidential)
{
    // Phase 4: v4 witness scriptPubKey = confidential
    CTxOut out(2000, MakeV4Script());
    BOOST_CHECK(out.IsConfidential());
    BOOST_CHECK(out.IsNativeSOQ());  // v4 is confidential SOQ, not USDSOQ
    BOOST_CHECK(!out.IsUSDSOQ());
}

BOOST_AUTO_TEST_CASE(ctxout_equality_structural)
{
    // Phase 4: Equality is (nValue, scriptPubKey) — same script = equal
    CScript p2pkh = MakeP2PKH();
    CTxOut a(1000, p2pkh);
    CTxOut b(1000, p2pkh);
    CTxOut c(1000, MakeV7Script());

    BOOST_CHECK(a == b);  // Same value+script
    BOOST_CHECK(a != c);  // Different script → different classification
}

// =========================================================================
// 3. CTxOut SERIALIZATION (wire format)
// =========================================================================

BOOST_AUTO_TEST_CASE(ctxout_serialization_roundtrip)
{
    // Phase 4: Serialization is (nValue, scriptPubKey) — no byte tags
    CTxOut original(5000, MakeV7Script());

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    CTxOut deserialized;
    ss >> deserialized;

    BOOST_CHECK_EQUAL(deserialized.nValue, 5000);
    BOOST_CHECK(deserialized.IsUSDSOQ());
    BOOST_CHECK(original == deserialized);
}

BOOST_AUTO_TEST_CASE(ctxout_serialization_confidential_roundtrip)
{
    CTxOut original(3000, MakeV4Script());

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    CTxOut deserialized;
    ss >> deserialized;

    BOOST_CHECK_EQUAL(deserialized.nValue, 3000);
    BOOST_CHECK(deserialized.IsConfidential());
    BOOST_CHECK(original == deserialized);
}

// =========================================================================
// 4. CTxOutCompressor — UTXO DB persistence
// =========================================================================

BOOST_AUTO_TEST_CASE(compressor_preserves_usdsoq)
{
    // Phase 4: Compressor preserves scriptPubKey, which carries classification
    CTxOut original(50000, MakeV7Script());

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    CTxOutCompressor compOut(original);
    ss << compOut;

    CTxOut restored;
    CTxOutCompressor compIn(restored);
    ss >> compIn;

    BOOST_CHECK(restored.IsUSDSOQ());
    BOOST_CHECK_EQUAL(restored.nValue, 50000);
}

BOOST_AUTO_TEST_CASE(compressor_preserves_confidential)
{
    CTxOut original(99999, MakeV4Script());

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << CTxOutCompressor(original);

    CTxOut restored;
    ss >> REF(CTxOutCompressor(restored));

    BOOST_CHECK(restored.IsConfidential());
    BOOST_CHECK_EQUAL(restored.nValue, 99999);
}

BOOST_AUTO_TEST_CASE(compressor_default_soq_roundtrip)
{
    // Default SOQ outputs must survive compressor roundtrip unchanged
    CTxOut original(100000, MakeP2PKH());

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << CTxOutCompressor(original);

    CTxOut restored;
    ss >> REF(CTxOutCompressor(restored));

    BOOST_CHECK(restored.IsNativeSOQ());
    BOOST_CHECK(!restored.IsConfidential());
    BOOST_CHECK(!restored.IsUSDSOQ());
    BOOST_CHECK_EQUAL(restored.nValue, 100000);
}

// =========================================================================
// 5. SUPPLY COUNTER
// =========================================================================

BOOST_AUTO_TEST_CASE(supply_counter_initial_state)
{
    CUSDSOQSupply supply;
    BOOST_CHECK_EQUAL(supply.TotalMinted(), 0);
    BOOST_CHECK_EQUAL(supply.TotalBurned(), 0);
    BOOST_CHECK_EQUAL(supply.Outstanding(), 0);
    BOOST_CHECK(supply.CheckInvariant());
}

BOOST_AUTO_TEST_CASE(supply_counter_mint)
{
    CUSDSOQSupply supply;
    BOOST_CHECK(supply.Mint(1000000));
    BOOST_CHECK_EQUAL(supply.TotalMinted(), 1000000);
    BOOST_CHECK_EQUAL(supply.Outstanding(), 1000000);
    BOOST_CHECK(supply.CheckInvariant());
}

BOOST_AUTO_TEST_CASE(supply_counter_mint_then_burn)
{
    CUSDSOQSupply supply;
    BOOST_CHECK(supply.Mint(5000000));
    BOOST_CHECK(supply.Burn(2000000));
    BOOST_CHECK_EQUAL(supply.Outstanding(), 3000000);
    BOOST_CHECK(supply.CheckInvariant());
}

BOOST_AUTO_TEST_CASE(supply_counter_burn_underflow_rejected)
{
    CUSDSOQSupply supply;
    BOOST_CHECK(supply.Mint(1000));
    BOOST_CHECK(!supply.Burn(2000));  // Can't burn more than outstanding
    BOOST_CHECK_EQUAL(supply.Outstanding(), 1000);  // Unchanged
}

BOOST_AUTO_TEST_CASE(supply_counter_zero_operations)
{
    CUSDSOQSupply supply;
    BOOST_CHECK(!supply.Mint(0));  // Zero mint rejected
    BOOST_CHECK(!supply.Burn(0));  // Zero burn rejected
}

BOOST_AUTO_TEST_CASE(supply_counter_reset)
{
    CUSDSOQSupply supply;
    supply.Mint(999999);
    supply.Reset();
    BOOST_CHECK_EQUAL(supply.Outstanding(), 0);
    BOOST_CHECK_EQUAL(supply.TotalMinted(), 0);
}

BOOST_AUTO_TEST_CASE(supply_counter_serialization)
{
    CUSDSOQSupply original;
    original.Mint(10000000);
    original.Burn(3000000);

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    CUSDSOQSupply restored;
    ss >> restored;

    BOOST_CHECK_EQUAL(restored.TotalMinted(), 10000000);
    BOOST_CHECK_EQUAL(restored.TotalBurned(), 3000000);
    BOOST_CHECK_EQUAL(restored.Outstanding(), 7000000);
}

// =========================================================================
// 6. AUTHORITY KEY MANAGEMENT
// =========================================================================

BOOST_AUTO_TEST_CASE(authority_initial_state)
{
    CUSDSOQAuthority auth;
    BOOST_CHECK(!auth.IsInitialized());
    BOOST_CHECK_EQUAL(auth.GetThreshold(), 0u);
    BOOST_CHECK_EQUAL(auth.GetKeyCount(), 0u);
}

BOOST_AUTO_TEST_CASE(authority_initialize_valid)
{
    CUSDSOQAuthority auth;
    std::vector<std::vector<uint8_t>> keys;
    for (int i = 0; i < 5; i++)
        keys.push_back(std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, (uint8_t)(i + 1)));

    BOOST_CHECK(auth.Initialize(keys, 3));
    BOOST_CHECK(auth.IsInitialized());
    BOOST_CHECK_EQUAL(auth.GetThreshold(), 3u);
    BOOST_CHECK_EQUAL(auth.GetKeyCount(), 5u);
}

BOOST_AUTO_TEST_CASE(authority_reject_threshold_too_high)
{
    CUSDSOQAuthority auth;
    std::vector<std::vector<uint8_t>> keys;
    keys.push_back(std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, 0x01));
    keys.push_back(std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, 0x02));

    BOOST_CHECK(!auth.Initialize(keys, 5));  // 5-of-2 impossible
    BOOST_CHECK(!auth.IsInitialized());
}

BOOST_AUTO_TEST_CASE(authority_reject_threshold_too_low)
{
    CUSDSOQAuthority auth;
    std::vector<std::vector<uint8_t>> keys;
    keys.push_back(std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, 0x01));
    keys.push_back(std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, 0x02));
    keys.push_back(std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, 0x03));

    BOOST_CHECK(!auth.Initialize(keys, 1));  // Below MIN_THRESHOLD=2
}

BOOST_AUTO_TEST_CASE(authority_reject_too_many_keys)
{
    CUSDSOQAuthority auth;
    std::vector<std::vector<uint8_t>> keys;
    for (unsigned int i = 0; i < USDSOQ_MAX_AUTHORITY_KEYS + 1; i++)
        keys.push_back(std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, (uint8_t)i));

    BOOST_CHECK(!auth.Initialize(keys, 2));  // 16 keys > max 15
}

BOOST_AUTO_TEST_CASE(authority_reject_wrong_key_size)
{
    CUSDSOQAuthority auth;
    std::vector<std::vector<uint8_t>> keys;
    keys.push_back(std::vector<uint8_t>(100, 0x01));  // Wrong size
    keys.push_back(std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, 0x02));

    BOOST_CHECK(!auth.Initialize(keys, 2));
}

BOOST_AUTO_TEST_CASE(authority_serialization)
{
    CUSDSOQAuthority original;
    std::vector<std::vector<uint8_t>> keys;
    for (int i = 0; i < 3; i++)
        keys.push_back(std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, (uint8_t)(i + 0x10)));
    original.Initialize(keys, 2);

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    CUSDSOQAuthority restored;
    ss >> restored;

    BOOST_CHECK(restored.IsInitialized());
    BOOST_CHECK_EQUAL(restored.GetThreshold(), 2u);
    BOOST_CHECK_EQUAL(restored.GetKeyCount(), 3u);
}

// =========================================================================
// 7. BIP9 DEPLOYMENT GATING
// =========================================================================

BOOST_AUTO_TEST_CASE(deployment_usdsoq_exists)
{
    // Verify DEPLOYMENT_USDSOQ is registered
    SelectParams(CBaseChainParams::REGTEST);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // Bit 6 should be the USDSOQ deployment
    BOOST_CHECK(Consensus::DEPLOYMENT_USDSOQ < Consensus::MAX_VERSION_BITS_DEPLOYMENTS);
}

BOOST_AUTO_TEST_CASE(regtest_usdsoq_always_active)
{
    SelectParams(CBaseChainParams::REGTEST);
    const Consensus::Params& consensus = Params().GetConsensus(0);

    // Regtest should have ALWAYS_ACTIVE for USDSOQ
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_USDSOQ].nStartTime,
                      Consensus::BIP9Deployment::ALWAYS_ACTIVE);
}

BOOST_AUTO_TEST_CASE(script_verify_usdsoq_flag)
{
    // SCRIPT_VERIFY_USDSOQ should be a distinct bit that doesn't collide
    BOOST_CHECK(SCRIPT_VERIFY_USDSOQ != 0);
    BOOST_CHECK((SCRIPT_VERIFY_USDSOQ & SCRIPT_VERIFY_LATTICEFOLD) == 0);
}

// =========================================================================
// 8. OPCODE CONSTANTS
// =========================================================================

BOOST_AUTO_TEST_CASE(usdsoq_opcode_assignments)
{
    BOOST_CHECK_EQUAL((int)OP_USDSOQ_MINT, 0xf4);
    BOOST_CHECK_EQUAL((int)OP_USDSOQ_BURN, 0xf5);
    BOOST_CHECK_EQUAL((int)OP_USDSOQ_FREEZE, 0xf6);
    BOOST_CHECK_EQUAL((int)OP_USDSOQ_ROTATE, 0xf7);
}

// =========================================================================
// 9. EVALSCRIPT OPCODE DISPATCH
// =========================================================================

BOOST_AUTO_TEST_CASE(evalscript_mint_empty_stack)
{
    SelectParams(CBaseChainParams::REGTEST);
    unsigned int flags = SCRIPT_VERIFY_USDSOQ;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    CScript script = CScript() << OP_USDSOQ_MINT;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(evalscript_burn_empty_stack)
{
    unsigned int flags = SCRIPT_VERIFY_USDSOQ;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    CScript script = CScript() << OP_USDSOQ_BURN;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(evalscript_freeze_empty_stack)
{
    unsigned int flags = SCRIPT_VERIFY_USDSOQ;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    CScript script = CScript() << OP_USDSOQ_FREEZE;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(evalscript_rotate_empty_stack)
{
    unsigned int flags = SCRIPT_VERIFY_USDSOQ;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    CScript script = CScript() << OP_USDSOQ_ROTATE;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(evalscript_usdsoq_rejected_without_flag)
{
    // Without SCRIPT_VERIFY_USDSOQ flag, opcodes return USDSOQ_NOT_ACTIVE
    unsigned int flags = 0;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    CScript script = CScript() << OP_USDSOQ_MINT;
    std::vector<std::vector<unsigned char>> stack;
    bool result = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_USDSOQ_NOT_ACTIVE);
}

BOOST_AUTO_TEST_CASE(evalscript_mint_wrong_opcode_tag)
{
    unsigned int flags = SCRIPT_VERIFY_USDSOQ;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    // Build a proper 4-element stack with wrong opcode tag
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back({0x02});  // Wrong tag: 0x02=BURN, but opcode is MINT=0x01
    stack.push_back(std::vector<unsigned char>(36, 0xaa));  // payload
    stack.push_back(std::vector<unsigned char>(DILITHIUM_SIG_SIZE, 0xbb));  // sig
    stack.push_back(std::vector<unsigned char>(100, 0xcc));  // authority set

    CScript script = CScript() << OP_USDSOQ_MINT;
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_USDSOQ_INVALID_OPCODE);
}

BOOST_AUTO_TEST_CASE(evalscript_mint_wrong_sig_size)
{
    unsigned int flags = SCRIPT_VERIFY_USDSOQ;
    ScriptError serror = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;

    // Build a 4-element stack with wrong signature size
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back({0x01});  // Correct tag for MINT
    stack.push_back(std::vector<unsigned char>(36, 0xaa));  // payload
    stack.push_back(std::vector<unsigned char>(100, 0xbb));  // Wrong sig size
    stack.push_back(std::vector<unsigned char>(100, 0xcc));  // authority set

    CScript script = CScript() << OP_USDSOQ_MINT;
    BOOST_CHECK(!EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_USDSOQ_AUTHORITY_FAILED);
}

// =========================================================================
// 10. SCRIPT ERROR STRINGS
// =========================================================================

BOOST_AUTO_TEST_CASE(usdsoq_error_strings)
{
    BOOST_CHECK(std::string(ScriptErrorString(SCRIPT_ERR_USDSOQ_NOT_ACTIVE)).size() > 0);
    BOOST_CHECK(std::string(ScriptErrorString(SCRIPT_ERR_USDSOQ_AUTHORITY_FAILED)).size() > 0);
    BOOST_CHECK(std::string(ScriptErrorString(SCRIPT_ERR_USDSOQ_SUPPLY_OVERFLOW)).size() > 0);
    BOOST_CHECK(std::string(ScriptErrorString(SCRIPT_ERR_USDSOQ_INVALID_OPCODE)).size() > 0);
    BOOST_CHECK(std::string(ScriptErrorString(SCRIPT_ERR_USDSOQ_FROZEN_UTXO)).size() > 0);
}

// =========================================================================
// 11. VERSIONBITS DEPLOYMENT INFO
// =========================================================================

BOOST_AUTO_TEST_CASE(versionbits_usdsoq_name)
{
    // VersionBitsDeploymentInfo should have the correct name
    const struct BIP9DeploymentInfo& info =
        VersionBitsDeploymentInfo[Consensus::DEPLOYMENT_USDSOQ];
    BOOST_CHECK(std::string(info.name) == "usdsoq");
}

// =========================================================================
// 12. USDSOQ VISIBILITY ENFORCEMENT (Phase 4 — structural)
// =========================================================================
// Phase 4: USDSOQ = v7 witness, which is transparent by definition.
// Confidentiality = v4 witness, which is mutually exclusive with v7.

BOOST_AUTO_TEST_CASE(usdsoq_is_transparent_by_definition)
{
    // v7 outputs are always transparent
    CTxOut out(1000, MakeV7Script());
    BOOST_CHECK(out.IsUSDSOQ());
    BOOST_CHECK(!out.IsConfidential());
    BOOST_CHECK(out.IsTransparent());
}

BOOST_AUTO_TEST_CASE(soq_can_be_confidential)
{
    // Native SOQ CAN be confidential via v4 witness
    CTxOut out(1000, MakeV4Script());
    BOOST_CHECK(out.IsConfidential());
    BOOST_CHECK(out.IsNativeSOQ());
    BOOST_CHECK(!out.IsUSDSOQ());
}

BOOST_AUTO_TEST_CASE(v4_and_v7_mutually_exclusive)
{
    // An output cannot simultaneously be v4 (confidential) and v7 (USDSOQ)
    CTxOut v4out(1000, MakeV4Script());
    CTxOut v7out(1000, MakeV7Script());

    BOOST_CHECK(v4out.IsConfidential() && !v4out.IsUSDSOQ());
    BOOST_CHECK(v7out.IsUSDSOQ() && !v7out.IsConfidential());
}

// =========================================================================
// 13. CROSS-ASSET ISOLATION (Phase 4 — structural)
// =========================================================================

BOOST_AUTO_TEST_CASE(cross_asset_isolation_ctxout_predicates)
{
    // SOQ and USDSOQ outputs differ by witness version
    CTxOut soqOut(5000, MakeP2PKH());
    CTxOut usdsoqOut(5000, MakeV7Script());

    // They must NOT be equal — prevents cross-asset confusion
    BOOST_CHECK(soqOut != usdsoqOut);
    BOOST_CHECK(soqOut.IsNativeSOQ());
    BOOST_CHECK(!soqOut.IsUSDSOQ());
    BOOST_CHECK(usdsoqOut.IsUSDSOQ());
    BOOST_CHECK(!usdsoqOut.IsNativeSOQ());
}

BOOST_AUTO_TEST_CASE(shielding_usdsoq_impossible_phase4)
{
    // Phase 4: An output is either v7 (USDSOQ) or v4 (confidential), never both.
    // "Shielding" USDSOQ would require changing the scriptPubKey from v7 to v4,
    // which changes the asset type. ConnectBlock enforcement prevents this.
    CTxOut transparent(1000, MakeV7Script());
    BOOST_CHECK(transparent.IsTransparent());
    BOOST_CHECK(transparent.IsUSDSOQ());

    CTxOut shielded(1000, MakeV4Script());
    BOOST_CHECK(shielded.IsConfidential());
    BOOST_CHECK(!shielded.IsUSDSOQ());  // v4 is NOT USDSOQ
    BOOST_CHECK(shielded.IsNativeSOQ());
}

BOOST_AUTO_TEST_CASE(fee_must_be_soq_not_usdsoq)
{
    // Transaction fees must be native SOQ, not USDSOQ.
    // ConnectBlock's per-asset fee computation enforces this.
    CTxOut feeOutput(100, MakeP2PKH());
    BOOST_CHECK(feeOutput.IsNativeSOQ());

    CTxOut usdsoqOutput(100, MakeV7Script());
    BOOST_CHECK(!usdsoqOutput.IsNativeSOQ());
    // ConnectBlock would reject this as a fee-paying output
}

BOOST_AUTO_TEST_SUITE_END()
