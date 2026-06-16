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

    // Emit for pinning (copy into EXPECT_* on first green run).
    BOOST_TEST_MESSAGE("CTXOUT_MATRIX_BEGIN");
    BOOST_TEST_MESSAGE("extended_hex=" << HexStr(extended.begin(), extended.end()));
    BOOST_TEST_MESSAGE("standard_hex=" << HexStr(standard.begin(), standard.end()));
    BOOST_TEST_MESSAGE("CTXOUT_MATRIX_END");

    // Pinned golden baseline — uncomment + fill from the emitted hexes to lock it:
    // const std::string EXPECT_EXTENDED = "...";
    // const std::string EXPECT_STANDARD = "...";
    // BOOST_CHECK_EQUAL(HexStr(extended.begin(), extended.end()), EXPECT_EXTENDED);
    // BOOST_CHECK_EQUAL(HexStr(standard.begin(), standard.end()), EXPECT_STANDARD);
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

BOOST_AUTO_TEST_SUITE_END()
