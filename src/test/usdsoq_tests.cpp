// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-AUD2-002: USDSOQ Stablecoin Consensus Tests
// Covers: CTxOut fields, supply counter, asset isolation, frozen UTXOs,
//         opcode dispatch, BIP9 gating, compressor serialization.

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
// 2. CTxOut FIELD TESTS
// =========================================================================

BOOST_AUTO_TEST_CASE(ctxout_default_fields)
{
    CTxOut out;
    out.SetNull();
    BOOST_CHECK_EQUAL(out.nVisibility, 0x00);
    BOOST_CHECK_EQUAL(out.nAssetType, 0x00);
    BOOST_CHECK(out.IsNativeSOQ());
    BOOST_CHECK(out.IsTransparent());
    BOOST_CHECK(!out.IsUSDSOQ());
    BOOST_CHECK(!out.IsConfidential());
}

BOOST_AUTO_TEST_CASE(ctxout_extended_constructor)
{
    CScript script;
    script << OP_RETURN;
    CTxOut out(1000, script, VISIBILITY_CONFIDENTIAL, ASSET_TYPE_USDSOQ);
    BOOST_CHECK_EQUAL(out.nValue, 1000);
    BOOST_CHECK_EQUAL(out.nVisibility, VISIBILITY_CONFIDENTIAL);
    BOOST_CHECK_EQUAL(out.nAssetType, ASSET_TYPE_USDSOQ);
    BOOST_CHECK(out.IsUSDSOQ());
    BOOST_CHECK(out.IsConfidential());
    BOOST_CHECK(!out.IsNativeSOQ());
}

BOOST_AUTO_TEST_CASE(ctxout_equality_includes_new_fields)
{
    CScript script;
    script << OP_RETURN;
    CTxOut a(1000, script, 0x00, 0x00);
    CTxOut b(1000, script, 0x00, 0x01);
    CTxOut c(1000, script, 0x01, 0x00);
    CTxOut d(1000, script, 0x00, 0x00);

    BOOST_CHECK(a == d);  // Same fields
    BOOST_CHECK(a != b);  // Different asset type
    BOOST_CHECK(a != c);  // Different visibility
}

// =========================================================================
// 3. CTxOut SERIALIZATION (wire format)
// =========================================================================

BOOST_AUTO_TEST_CASE(ctxout_serialization_roundtrip)
{
    CScript script;
    script << OP_RETURN;
    CTxOut original(5000, script, VISIBILITY_CONFIDENTIAL, ASSET_TYPE_USDSOQ);

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    CTxOut deserialized;
    ss >> deserialized;

    BOOST_CHECK_EQUAL(deserialized.nValue, 5000);
    BOOST_CHECK_EQUAL(deserialized.nVisibility, VISIBILITY_CONFIDENTIAL);
    BOOST_CHECK_EQUAL(deserialized.nAssetType, ASSET_TYPE_USDSOQ);
    BOOST_CHECK(original == deserialized);
}

BOOST_AUTO_TEST_CASE(ctxout_serialization_frozen_mask)
{
    CScript script;
    script << OP_RETURN;
    uint8_t frozenVis = VISIBILITY_FROZEN_MASK | VISIBILITY_TRANSPARENT;
    CTxOut original(100, script, frozenVis, ASSET_TYPE_USDSOQ);

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    CTxOut deserialized;
    ss >> deserialized;

    BOOST_CHECK_EQUAL(deserialized.nVisibility, frozenVis);
    BOOST_CHECK(deserialized.nVisibility & VISIBILITY_FROZEN_MASK);
    BOOST_CHECK_EQUAL(deserialized.nVisibility & ~VISIBILITY_FROZEN_MASK, VISIBILITY_TRANSPARENT);
}

// =========================================================================
// 4. CTxOutCompressor — UTXO DB persistence
// =========================================================================

BOOST_AUTO_TEST_CASE(compressor_preserves_new_fields)
{
    // CRITICAL: CTxOutCompressor must serialize nVisibility + nAssetType
    // or the UTXO database drops them on restart.
    CScript script;
    script << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0xab) << OP_EQUALVERIFY << OP_CHECKSIG;
    CTxOut original(50000, script, VISIBILITY_CONFIDENTIAL, ASSET_TYPE_USDSOQ);

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    CTxOutCompressor compOut(original);
    ss << compOut;

    CTxOut restored;
    CTxOutCompressor compIn(restored);
    ss >> compIn;

    BOOST_CHECK_EQUAL(restored.nVisibility, VISIBILITY_CONFIDENTIAL);
    BOOST_CHECK_EQUAL(restored.nAssetType, ASSET_TYPE_USDSOQ);
    BOOST_CHECK_EQUAL(restored.nValue, 50000);
}

BOOST_AUTO_TEST_CASE(compressor_frozen_usdsoq_roundtrip)
{
    CScript script;
    script << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0xcd) << OP_EQUALVERIFY << OP_CHECKSIG;
    uint8_t frozenConf = VISIBILITY_FROZEN_MASK | VISIBILITY_CONFIDENTIAL;
    CTxOut original(99999, script, frozenConf, ASSET_TYPE_USDSOQ);

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << CTxOutCompressor(original);

    CTxOut restored;
    ss >> REF(CTxOutCompressor(restored));

    BOOST_CHECK_EQUAL(restored.nVisibility, frozenConf);
    BOOST_CHECK_EQUAL(restored.nAssetType, ASSET_TYPE_USDSOQ);
    BOOST_CHECK(restored.nVisibility & VISIBILITY_FROZEN_MASK);
}

BOOST_AUTO_TEST_CASE(compressor_default_soq_roundtrip)
{
    // Default SOQ outputs must survive compressor roundtrip unchanged
    CScript script;
    script << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x11) << OP_EQUALVERIFY << OP_CHECKSIG;
    CTxOut original(100000, script);  // Uses default 0x00/0x00

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << CTxOutCompressor(original);

    CTxOut restored;
    ss >> REF(CTxOutCompressor(restored));

    BOOST_CHECK_EQUAL(restored.nVisibility, VISIBILITY_TRANSPARENT);
    BOOST_CHECK_EQUAL(restored.nAssetType, ASSET_TYPE_SOQ);
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

BOOST_AUTO_TEST_SUITE_END()
