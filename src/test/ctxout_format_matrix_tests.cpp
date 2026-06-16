// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// ctxout_format_matrix_tests.cpp — CTxOut serialization "golden matrix" (CTxOut migration Phase 0).
//
// The minefield analysis (DL-CTXOUT-EXTENSION-FIRST-PRINCIPLES.md) showed the recurring damage is at
// serialization SEAMS: the consensus CTxOut carries 2 extra bytes (nVisibility, nAssetType) that the
// foreign/Litecoin format strips via SERIALIZE_TXOUT_STANDARD, and any serializer/reimpl that handles
// those bytes inconsistently is a latent consensus/interop bug. This test PINS the C++ side of the
// matrix so the Phase-4 byte-removal (and any reimpl drift) is caught, not silent.
//
// Assertions here are RUN-INDEPENDENT (structural relationships, not hardcoded hex I can't verify on a
// fresh worktree) + the actual hexes are EMITTED for pinning (emit-then-pin, like the envelope vector).
// Buddy: on first green run, copy the emitted CTXOUT_MATRIX hexes into the EXPECT_* constants below to
// lock the golden baseline; register in src/Makefile.test.include.
//
// Phase-4 note: when the 2 bytes are removed, the "extended" form BECOMES the "standard" form — these
// vectors will change, and that change should be an explicit, reviewed diff (that's the whole point).

#include "primitives/transaction.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include "version.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace {

// A fixed, representative CTxOut: confidential (vis=0x01) USDSOQ (asset=0x01) output.
static CTxOut FixtureTxOut()
{
    CTxOut o;
    o.nValue = 12345678;
    o.scriptPubKey = CScript() << OP_TRUE;   // 1-byte script (0x51)
    o.nVisibility = 0x01;                     // VISIBILITY_CONFIDENTIAL
    o.nAssetType  = 0x01;                     // ASSET_TYPE_USDSOQ
    return o;
}

// A v7 USDSOQ-holding output (CTxOut migration Phase 3): OP_7 <32×0xAA>, transparent,
// nAssetType=0x01 as the transition dual-signal (PHASE-4-REMOVE). Must serialize
// byte-identically to the Go signer fixture (soq-signer v7_holding_test.go).
static CTxOut V7HoldingFixture()
{
    CTxOut o;
    o.nValue = 12345678;
    CScript spk; spk << OP_7 << std::vector<unsigned char>(32, 0xaa);  // OP_7 <32> = v7 USDSOQ holding
    o.scriptPubKey = spk;
    o.nVisibility = 0x00;   // USDSOQ is always transparent
    o.nAssetType  = 0x01;   // transition dual-signal; PHASE-4-REMOVE
    return o;
}

static std::vector<unsigned char> Ser(const CTxOut& o, int extraFlags)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION | extraFlags);
    ss << o;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(ctxout_format_matrix_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// The extended (native) form = the standard (foreign) form + {vis, asset} appended.
// This relationship is the load-bearing invariant of the whole extension: the
// consensus serializer adds exactly 2 trailing bytes that SERIALIZE_TXOUT_STANDARD strips.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ctxout_extended_vs_standard_relationship)
{
    const CTxOut o = FixtureTxOut();

    std::vector<unsigned char> extended = Ser(o, 0);                          // native (vis+asset)
    std::vector<unsigned char> standard = Ser(o, SERIALIZE_TXOUT_STANDARD);   // foreign (stripped)

    // 1. The native form is exactly 2 bytes longer than the foreign form.
    BOOST_CHECK_EQUAL(extended.size(), standard.size() + 2);

    // 2. The foreign form is a strict PREFIX of the native form — i.e. vis/asset are
    //    APPENDED at the end, not interleaved. (If a refactor moved them before the
    //    script, this breaks — exactly the kind of seam bug we're guarding.)
    BOOST_CHECK(std::equal(standard.begin(), standard.end(), extended.begin()));

    // 3. The two trailing native bytes are exactly {nVisibility, nAssetType}.
    BOOST_CHECK_EQUAL(extended[extended.size() - 2], o.nVisibility);
    BOOST_CHECK_EQUAL(extended[extended.size() - 1], o.nAssetType);

    BOOST_TEST_MESSAGE("CTXOUT_MATRIX_BEGIN");
    BOOST_TEST_MESSAGE("extended_hex=" << HexStr(extended.begin(), extended.end()));
    BOOST_TEST_MESSAGE("standard_hex=" << HexStr(standard.begin(), standard.end()));
    BOOST_TEST_MESSAGE("CTXOUT_MATRIX_END");

    // PINNED golden baseline — the shared cross-reimpl vector. The extended form is
    // confirmed byte-exact by the TS SDK (soq-lightning-sdk test/ctxout_matrix.test.mjs),
    // which is itself node-pinned via the envelope vector → this IS the node's CTxOut bytes.
    // standard = extended minus the trailing {vis, asset}. If C++ disagrees with this, that's
    // a real node↔reimpl serialization mismatch — exactly what the matrix exists to catch.
    // (Phase-4 note: when the 2 bytes are removed, EXPECT_EXTENDED becomes EXPECT_STANDARD —
    // an explicit, reviewed diff.)
    const std::string EXPECT_EXTENDED = "4e61bc000000000001510101";
    const std::string EXPECT_STANDARD = "4e61bc00000000000151";
    BOOST_CHECK_EQUAL(HexStr(extended.begin(), extended.end()), EXPECT_EXTENDED);
    BOOST_CHECK_EQUAL(HexStr(standard.begin(), standard.end()), EXPECT_STANDARD);
}

// ---------------------------------------------------------------------------
// Round-trip symmetry: each form deserializes back correctly under its own flag.
// Native carries vis/asset; foreign defaults them to 0 (it has no such bytes).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ctxout_roundtrip_symmetry)
{
    const CTxOut o = FixtureTxOut();

    // Native round-trip preserves vis/asset.
    {
        std::vector<unsigned char> b = Ser(o, 0);
        CDataStream ss(b, SER_NETWORK, PROTOCOL_VERSION);
        CTxOut back; ss >> back;
        BOOST_CHECK(back.nValue == o.nValue);
        BOOST_CHECK(back.scriptPubKey == o.scriptPubKey);
        BOOST_CHECK_EQUAL(back.nVisibility, o.nVisibility);
        BOOST_CHECK_EQUAL(back.nAssetType, o.nAssetType);
    }

    // Foreign round-trip drops vis/asset → defaults (0). This is the format a
    // Litecoin/Doge tx round-trips through (AuxPoW boundary).
    {
        std::vector<unsigned char> b = Ser(o, SERIALIZE_TXOUT_STANDARD);
        CDataStream ss(b, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TXOUT_STANDARD);
        CTxOut back; ss >> back;
        BOOST_CHECK(back.nValue == o.nValue);
        BOOST_CHECK(back.scriptPubKey == o.scriptPubKey);
        BOOST_CHECK_EQUAL(back.nVisibility, 0);   // default — foreign format has no such byte
        BOOST_CHECK_EQUAL(back.nAssetType, 0);
    }
}

// ---------------------------------------------------------------------------
// Phase 2: IsConfidential() is derived from witness-v4, NOT the nVisibility byte.
// Proves the migration actually happened (confidentiality follows the witness version,
// which is what the range-proof prover uses) AND the equivalence on existing data
// (v4 output with nVisibility==0x01 is still confidential).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(isconfidential_is_v4_derived)
{
    CScript v4spk; v4spk << OP_4 << std::vector<unsigned char>(32, 0xab);  // OP_4 <32-byte> = v4 confidential
    CScript v1spk; v1spk << OP_1 << std::vector<unsigned char>(32, 0xcd);  // OP_1 <32-byte> = v1 Dilithium
    BOOST_REQUIRE_EQUAL(v4spk.size(), 34u);
    BOOST_REQUIRE_EQUAL(v1spk.size(), 34u);

    auto mk = [](const CScript& spk, uint8_t vis) {
        CTxOut o; o.nValue = 1000; o.scriptPubKey = spk; o.nVisibility = vis; o.nAssetType = 0;
        return o;
    };

    // v4 output is confidential REGARDLESS of the nVisibility byte (v4 is the determinant).
    BOOST_CHECK(mk(v4spk, 0x00).IsConfidential());   // byte says transparent — v4 still wins
    BOOST_CHECK(mk(v4spk, 0x01).IsConfidential());   // existing-data case (both agree)
    BOOST_CHECK(!mk(v4spk, 0x00).IsTransparent());

    // Non-v4 output is NOT confidential even if the legacy byte is set (byte is ignored now).
    BOOST_CHECK(!mk(v1spk, 0x01).IsConfidential());  // stray byte on a v1 output — not confidential
    BOOST_CHECK(!mk(v1spk, 0x00).IsConfidential());
    BOOST_CHECK(mk(v1spk, 0x01).IsTransparent());

    // IsTransparent() is exactly the complement of IsConfidential().
    BOOST_CHECK_EQUAL(mk(v4spk, 0x01).IsTransparent(), !mk(v4spk, 0x01).IsConfidential());
}

// ---------------------------------------------------------------------------
// Phase 3: v7 USDSOQ-holding serialization cross-pin. A v7 output is just a CTxOut
// with an OP_7 script, so the SAME extended/standard relationship holds — and the
// bytes must match the Go signer's golden (soq-signer v7_holding_test.go), which is
// the value-mover that builds these. Also asserts asset classification follows the
// witness version (IsUSDSOQ true with the byte present as a dual-signal).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ctxout_v7_holding_cross_pin)
{
    const CTxOut o = V7HoldingFixture();

    std::vector<unsigned char> extended = Ser(o, 0);
    std::vector<unsigned char> standard = Ser(o, SERIALIZE_TXOUT_STANDARD);

    // Same load-bearing relationship as the base fixture: native = foreign + {vis, asset}.
    BOOST_CHECK_EQUAL(extended.size(), standard.size() + 2);
    BOOST_CHECK(std::equal(standard.begin(), standard.end(), extended.begin()));
    BOOST_CHECK_EQUAL(extended[extended.size() - 2], o.nVisibility);
    BOOST_CHECK_EQUAL(extended[extended.size() - 1], o.nAssetType);

    BOOST_TEST_MESSAGE("CTXOUT_V7_MATRIX_BEGIN");
    BOOST_TEST_MESSAGE("v7_extended_hex=" << HexStr(extended.begin(), extended.end()));
    BOOST_TEST_MESSAGE("v7_standard_hex=" << HexStr(standard.begin(), standard.end()));
    BOOST_TEST_MESSAGE("CTXOUT_V7_MATRIX_END");

    // Cross-pin to the Go signer golden (python-verified, byte-exact). If C++ disagrees,
    // that's a real node↔signer serialization mismatch on the new v7 type.
    const std::string EXPECT_EXTENDED =
        "4e61bc0000000000225720aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001";
    const std::string EXPECT_STANDARD =
        "4e61bc0000000000225720aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    BOOST_CHECK_EQUAL(HexStr(extended.begin(), extended.end()), EXPECT_EXTENDED);
    BOOST_CHECK_EQUAL(HexStr(standard.begin(), standard.end()), EXPECT_STANDARD);

    // Asset classification follows the witness version: a v7 output is USDSOQ.
    BOOST_CHECK(o.IsV7USDSOQHolding());
    BOOST_CHECK(o.IsUSDSOQ());
    BOOST_CHECK(!o.IsNativeSOQ());
}

BOOST_AUTO_TEST_SUITE_END()
