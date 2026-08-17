// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// ctxout_format_matrix_tests.cpp — CTxOut serialization golden matrix (Phase 4 re-pin).
//
// Phase 4 REMOVED the nVisibility/nAssetType extension bytes. CTxOut is now the single
// STANDARD Bitcoin format (nValue + scriptPubKey) — identical to the foreign/AuxPoW-parent
// encoding, so the dual-format SERIALIZE_TXOUT_STANDARD seam is gone (one format everywhere,
// the recurring minefield closed by construction). This pins the byte-less format byte-exact,
// matching the reimpls (soqucoin-sdk, soq-signer, soq-lightning-sdk) which re-pinned the same.
//
// The pre-Phase-4 extended forms ("...0101" / "...0001") no longer exist — this is the
// explicit, reviewed diff Phase 0 set this matrix up to make visible.

#include "primitives/transaction.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include "version.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace {

// OP_TRUE fixture (matches the reimpl matrices): value 12345678, scriptPubKey = OP_TRUE.
static CTxOut FixtureTxOut()
{
    CTxOut o;
    o.nValue = 12345678;
    o.scriptPubKey = CScript() << OP_TRUE;   // 1-byte script (0x51)
    return o;
}

// v7 USDSOQ-holding fixture: OP_7 <32×0xAA>. Asset is the witness version, no byte.
static CTxOut V7HoldingFixture()
{
    CTxOut o;
    o.nValue = 12345678;
    CScript spk; spk << OP_7 << std::vector<unsigned char>(32, 0xaa);
    o.scriptPubKey = spk;
    return o;
}

static std::vector<unsigned char> Ser(const CTxOut& o)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << o;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(ctxout_format_matrix_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// The single byte-less format == the OLD SERIALIZE_TXOUT_STANDARD form. Pinned golden,
// cross-checked against every reimpl. A mismatch is a real node↔reimpl serialization split.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ctxout_byteless_golden)
{
    const std::vector<unsigned char> b = Ser(FixtureTxOut());

    BOOST_TEST_MESSAGE("CTXOUT_MATRIX_BEGIN");
    BOOST_TEST_MESSAGE("ctxout_hex=" << HexStr(b.begin(), b.end()));
    BOOST_TEST_MESSAGE("CTXOUT_MATRIX_END");

    // Post-Phase-4 golden (10 bytes: value(8)+len(1)+script(1) — was 12 with the extension).
    BOOST_CHECK_EQUAL(HexStr(b.begin(), b.end()), "4e61bc00000000000151");
    BOOST_CHECK_EQUAL(b.size(), 10u);
}

// ---------------------------------------------------------------------------
// Round-trip: serialize → deserialize preserves value + script (the only fields now).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ctxout_roundtrip)
{
    const CTxOut o = FixtureTxOut();
    std::vector<unsigned char> b = Ser(o);
    CDataStream ss(b, SER_NETWORK, PROTOCOL_VERSION);
    CTxOut back; ss >> back;
    BOOST_CHECK(back.nValue == o.nValue);
    BOOST_CHECK(back.scriptPubKey == o.scriptPubKey);
}

// ---------------------------------------------------------------------------
// IsConfidential() is derived from witness-v4, never a byte (the byte is gone). Proves
// confidentiality follows the witness version the range-proof verifier uses.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(isconfidential_is_v4_derived)
{
    CScript v4spk; v4spk << OP_4 << std::vector<unsigned char>(32, 0xab);  // v4 confidential
    CScript v1spk; v1spk << OP_1 << std::vector<unsigned char>(32, 0xcd);  // v1 Dilithium
    BOOST_REQUIRE_EQUAL(v4spk.size(), 34u);

    auto mk = [](const CScript& spk) { CTxOut o; o.nValue = 1000; o.scriptPubKey = spk; return o; };

    BOOST_CHECK(mk(v4spk).IsConfidential());     // v4 → confidential
    BOOST_CHECK(!mk(v4spk).IsTransparent());
    BOOST_CHECK(!mk(v1spk).IsConfidential());    // v1 → transparent
    BOOST_CHECK(mk(v1spk).IsTransparent());
}

// ---------------------------------------------------------------------------
// v7 USDSOQ-holding byte-less cross-pin + version-derived classification.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ctxout_v7_holding_cross_pin)
{
    const CTxOut o = V7HoldingFixture();
    const std::vector<unsigned char> b = Ser(o);

    BOOST_TEST_MESSAGE("v7_ctxout_hex=" << HexStr(b.begin(), b.end()));
    BOOST_CHECK_EQUAL(HexStr(b.begin(), b.end()),
        "4e61bc0000000000225720aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    // Asset follows the witness version: a v7 output is USDSOQ, with no byte present.
    BOOST_CHECK(o.IsV7USDSOQHolding());
    BOOST_CHECK(o.IsUSDSOQ());
    BOOST_CHECK(!o.IsNativeSOQ());
}

// ---------------------------------------------------------------------------
// v10 confidential USDSOQ (SoquObscura Tier A).
//
// These tests exist because the combination they cover was previously
// IMPOSSIBLE to express: classification is structural, scriptPubKey[0] is one
// opcode, and OP_4 != OP_7, so IsConfidential() && IsUSDSOQ() was always false.
// Confidential USDSOQ was therefore unrepresentable and the SOQ-ARCH-004 rules
// governing it were unreachable. See DL-SOQUOBSCURA-ASSET-TYPE-TRACE.md.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(v10_is_confidential_usdsoq)
{
    auto mk = [](const CScript& spk) { CTxOut o; o.nValue = 1000; o.scriptPubKey = spk; return o; };
    CScript v10spk; v10spk << OP_10 << std::vector<unsigned char>(32, 0xa1);
    BOOST_REQUIRE_EQUAL(v10spk.size(), 34u);
    const CTxOut o = mk(v10spk);

    // v10 is confidential AND USDSOQ at the same time — the thing v4/v7 could not do.
    BOOST_CHECK(o.IsV10ConfidentialUSDSOQ());
    BOOST_CHECK(o.IsConfidential());
    BOOST_CHECK(!o.IsTransparent());
    BOOST_CHECK(o.IsAnyUSDSOQ());

    // ⚠️ THE FEE-FILTER INVARIANT. The per-asset fee filter treats native-SOQ value
    // as miner-claimable, so if v10 leaked into IsNativeSOQ() then USDSOQ value could
    // be claimed as SOQ fees. This assertion is the guard on that.
    BOOST_CHECK(!o.IsNativeSOQ());

    // v10 is Tier A, so it must NOT match the Tier B predicate. Tier B (v4) is exempt
    // from the mandatory issuer disclosure; conflating them would exempt Tier A too.
    BOOST_CHECK(!o.IsV4ConfidentialSOQ());
    BOOST_CHECK(!o.IsUSDSOQ());        // v7 predicate is transparent-only
    BOOST_CHECK(!o.IsBTCSOQ());
}

BOOST_AUTO_TEST_CASE(v4_and_v10_are_distinct_tiers)
{
    auto mk = [](const CScript& spk) { CTxOut o; o.nValue = 1000; o.scriptPubKey = spk; return o; };
    CScript v4spk; v4spk << OP_4 << std::vector<unsigned char>(32, 0xb2);
    CScript v10spk; v10spk << OP_10 << std::vector<unsigned char>(32, 0xb2);

    const CTxOut v4 = mk(v4spk);   // Tier B: confidential native SOQ
    const CTxOut v10 = mk(v10spk);   // Tier A: confidential USDSOQ

    // Both confidential — confidentiality mechanics are identical.
    BOOST_CHECK(v4.IsConfidential());
    BOOST_CHECK(v10.IsConfidential());

    // Different assets, and that is the whole point: the disclosure rule keys off
    // this distinction, so it must be exactly one evaluation on one byte.
    BOOST_CHECK(v4.IsNativeSOQ());
    BOOST_CHECK(!v10.IsNativeSOQ());
    BOOST_CHECK(!v4.IsAnyUSDSOQ());
    BOOST_CHECK(v10.IsAnyUSDSOQ());
    BOOST_CHECK(v4.IsV4ConfidentialSOQ());
    BOOST_CHECK(!v10.IsV4ConfidentialSOQ());
}

// ---------------------------------------------------------------------------
// REGRESSION GUARD for the SOQ-ARCH-004 dead-code defect.
//
// The rules in validation.cpp that enforce "USDSOQ authority outputs must be
// transparent" (GENIUS Act §4(a)(2)) live inside a loop gated on a USDSOQ
// predicate and then test IsConfidential(). While that gate was IsUSDSOQ()
// (v7 only) the conjunction was UNSATISFIABLE, so the rules could never run —
// and every test still passed, because a rule that never fires never fails.
//
// This test asserts the conjunction is satisfiable. If someone narrows the loop
// predicate back to a transparent-only one, this fails immediately instead of
// silently disarming the compliance rules again.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(soq_arch_004_guard_conjunction_is_satisfiable)
{
    CScript v10spk; v10spk << OP_10 << std::vector<unsigned char>(32, 0xd4);
    CTxOut o; o.nValue = 1000; o.scriptPubKey = v10spk;

    // The exact conjunction the SOQ-ARCH-004 rules are gated on.
    BOOST_CHECK(o.IsAnyUSDSOQ() && o.IsConfidential());

    // And the conjunction that used to gate them, which must remain unsatisfiable —
    // documenting WHY the predicate had to change rather than just that it did.
    BOOST_CHECK(!(o.IsUSDSOQ() && o.IsConfidential()));

    // A transparent v7 output must still reach the loop but take the transparent
    // path, so supply tracking stays anchored to the mint/burn boundary.
    CScript v7spk; v7spk << OP_7 << std::vector<unsigned char>(32, 0xd4);
    CTxOut t; t.nValue = 1000; t.scriptPubKey = v7spk;
    BOOST_CHECK(t.IsAnyUSDSOQ());
    BOOST_CHECK(t.IsTransparent());
    BOOST_CHECK(!t.IsConfidential());
}

BOOST_AUTO_TEST_CASE(v10_wrong_shape_is_not_confidential_usdsoq)
{
    // Fail-closed: anything that is not exactly OP_10 <32> is not a v10 output, and
    // therefore is not a confidential output at all. An unknown or malformed
    // witness version must never fall through into a tier.
    auto mk = [](const CScript& spk) { CTxOut o; o.nValue = 1000; o.scriptPubKey = spk; return o; };

    CScript shortPush;  shortPush  << OP_10 << std::vector<unsigned char>(31, 0xc3);
    CScript longPush;   longPush   << OP_10 << std::vector<unsigned char>(33, 0xc3);
    CScript wrongVer;   wrongVer   << OP_5 << std::vector<unsigned char>(32, 0xc3);

    BOOST_CHECK(!mk(shortPush).IsV10ConfidentialUSDSOQ());
    BOOST_CHECK(!mk(longPush).IsV10ConfidentialUSDSOQ());
    BOOST_CHECK(!mk(wrongVer).IsV10ConfidentialUSDSOQ());

    // And none of them is confidential, so none can claim a confidential tier.
    BOOST_CHECK(!mk(shortPush).IsConfidential());
    BOOST_CHECK(!mk(longPush).IsConfidential());
    BOOST_CHECK(!mk(wrongVer).IsConfidential());
}

BOOST_AUTO_TEST_SUITE_END()
