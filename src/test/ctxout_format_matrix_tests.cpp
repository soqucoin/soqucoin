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

BOOST_AUTO_TEST_SUITE_END()
