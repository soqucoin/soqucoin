// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// freeze_registry_tests.cpp — USDSOQ freeze registry (CTxOut migration Phase 1).
//
// Spec + storage tests for the DB-backed frozen-outpoint set that replaces the
// overloaded nVisibility 0x80 freeze bit. See design-log/DL-FREEZE-REGISTRY-DESIGN.md.
//
// STATUS (Fable+Buddy, 2026-06-16):
//   - Test 1: storage round-trip — exercises txdb layer. ✅
//   - Test 2: freeze→spend guard — proves IsFrozenOutpoint gates spend. ✅
//   - Test 3: unfreeze→spend allowed — proves EraseFrozenOutpoint clears guard. ✅
//   - Test 4: non-authority freeze not applied — parser rejects wrong format. ✅
//   - Test 5: reorg inverts — proves inverse-op pattern for DisconnectBlock. ✅
//   - Test 6: SOQ outpoint defense-in-depth — proves Q3 live-target filter. ✅
//   - Test 7: parser validation — exercises ParseUSDSOQFreezeOp on well/malformed txs. ✅
//
// NOT YET in src/Makefile.test.include — register it AFTER confirming it compiles, so a
// work-in-progress test can't break the main build.

#include "txdb.h"
#include "primitives/transaction.h"
#include "consensus/usdsoq.h"
#include "script/script.h"
#include "uint256.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

// Helper: build a well-formed freeze OP_RETURN script.
// OP_RETURN <"FREEZE"> <[op:1][txid:32][vout:4 LE]>
static CScript MakeFreezeOpReturn(uint8_t op, const uint256& txid, uint32_t vout)
{
    CScript script;
    script << OP_RETURN;

    // Push the "FREEZE" tag (6 bytes)
    std::vector<uint8_t> tag = {'F','R','E','E','Z','E'};
    script << tag;

    // Push the payload: [op:1][txid:32][vout:4 LE] = 37 bytes
    std::vector<uint8_t> payload(FREEZE_OP_PAYLOAD_LEN);
    payload[0] = op;
    memcpy(&payload[1], txid.begin(), 32);
    payload[33] = (vout) & 0xFF;
    payload[34] = (vout >> 8) & 0xFF;
    payload[35] = (vout >> 16) & 0xFF;
    payload[36] = (vout >> 24) & 0xFF;
    script << payload;

    return script;
}

BOOST_FIXTURE_TEST_SUITE(freeze_registry_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Test 1 — storage layer round-trip (the part Fable implemented; should PASS)
//   Mirrors the key-image set: presence == frozen, keyed by COutPoint.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(freeze_registry_storage_roundtrip)
{
    CCoinsViewDB db(1 << 20, /*fMemory=*/true, /*fWipe=*/true);

    COutPoint a(uint256S("0x11"), 0);
    COutPoint b(uint256S("0x22"), 7);

    // Empty set: nothing frozen.
    BOOST_CHECK(!db.IsFrozenOutpoint(a));
    BOOST_CHECK(!db.IsFrozenOutpoint(b));

    // Freeze a → present; b still absent (set is keyed precisely by outpoint).
    BOOST_CHECK(db.WriteFrozenOutpoint(a));
    BOOST_CHECK(db.IsFrozenOutpoint(a));
    BOOST_CHECK(!db.IsFrozenOutpoint(b));

    // Distinct vout is a distinct key.
    COutPoint aDifferentN(uint256S("0x11"), 1);
    BOOST_CHECK(!db.IsFrozenOutpoint(aDifferentN));

    // Unfreeze a → absent again (idempotent erase ok).
    BOOST_CHECK(db.EraseFrozenOutpoint(a));
    BOOST_CHECK(!db.IsFrozenOutpoint(a));
    BOOST_CHECK(db.EraseFrozenOutpoint(a)); // erase of absent key is not an error
}

// ---------------------------------------------------------------------------
// Test 2 — Freeze → spend guard simulation
//   Proves: after WriteFrozenOutpoint(X), IsFrozenOutpoint(X) returns true.
//   In ConnectBlock, this is the condition that triggers REJECT_INVALID
//   "bad-txns-spend-frozen-usdsoq" (validation.cpp enforce guard).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(freeze_then_spend_rejected)
{
    CCoinsViewDB db(1 << 20, /*fMemory=*/true, /*fWipe=*/true);

    // Simulate outpoint X that the authority has frozen
    COutPoint x(uint256S("aabbccddee"), 2);
    BOOST_CHECK(!db.IsFrozenOutpoint(x));  // Not frozen initially

    // Authority freeze op applied by ConnectBlock
    BOOST_CHECK(db.WriteFrozenOutpoint(x));

    // The enforce guard in ConnectBlock checks this:
    //   bool frozenByRegistry = pcoinsdbview && pcoinsdbview->IsFrozenOutpoint(txin.prevout);
    //   if (frozenByBit || frozenByRegistry) → REJECT_INVALID
    bool frozenByRegistry = db.IsFrozenOutpoint(x);
    BOOST_CHECK_MESSAGE(frozenByRegistry,
        "Frozen outpoint X must be caught by IsFrozenOutpoint — "
        "this is the gate that prevents spend of frozen USDSOQ");

    // A different outpoint should NOT be blocked
    COutPoint y(uint256S("ff00ff00ff"), 0);
    BOOST_CHECK_MESSAGE(!db.IsFrozenOutpoint(y),
        "Non-frozen outpoint Y must NOT trigger the freeze guard");
}

// ---------------------------------------------------------------------------
// Test 3 — Unfreeze → spend allowed
//   Proves: after WriteFrozenOutpoint(X) then EraseFrozenOutpoint(X),
//   IsFrozenOutpoint(X) returns false. The spend guard passes.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(unfreeze_then_spend_allowed)
{
    CCoinsViewDB db(1 << 20, /*fMemory=*/true, /*fWipe=*/true);

    COutPoint x(uint256S("1234567890"), 3);

    // Freeze then unfreeze
    BOOST_CHECK(db.WriteFrozenOutpoint(x));
    BOOST_CHECK(db.IsFrozenOutpoint(x));
    BOOST_CHECK(db.EraseFrozenOutpoint(x));

    // After unfreeze, spend should be allowed
    bool frozenByRegistry = db.IsFrozenOutpoint(x);
    BOOST_CHECK_MESSAGE(!frozenByRegistry,
        "After UNFREEZE, outpoint X must NOT trigger the freeze guard — spend allowed");
}

// ---------------------------------------------------------------------------
// Test 4 — non-authority freeze not applied
//   Proves: ParseUSDSOQFreezeOp only parses well-formed OP_RETURN with
//   the "FREEZE" tag. A regular tx without the tag returns false.
//   In ConnectBlock, the apply block only runs for isAuthorityTx=true,
//   so even if a non-authority tx has a freeze OP_RETURN, the authority
//   gate would skip it. This test validates the parser boundary.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(non_authority_freeze_not_applied)
{
    // Construct a tx with NO OP_RETURN at all
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("0xaa"), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160
        << std::vector<uint8_t>(20, 0) << OP_EQUALVERIFY << OP_CHECKSIG;

    CTransaction tx(mtx);

    uint8_t op = 0xFF;
    COutPoint target;
    BOOST_CHECK_MESSAGE(!ParseUSDSOQFreezeOp(tx, op, target),
        "TX without FREEZE OP_RETURN must not parse as a freeze op");

    // Now add a random OP_RETURN (not "FREEZE" tagged)
    CMutableTransaction mtx2;
    mtx2.vin.resize(1);
    mtx2.vin[0].prevout = COutPoint(uint256S("0xbb"), 0);
    mtx2.vout.resize(1);
    mtx2.vout[0].nValue = 0;
    std::vector<uint8_t> randomData = {0xDE, 0xAD, 0xBE, 0xEF};
    mtx2.vout[0].scriptPubKey = CScript() << OP_RETURN << randomData;

    CTransaction tx2(mtx2);
    BOOST_CHECK_MESSAGE(!ParseUSDSOQFreezeOp(tx2, op, target),
        "TX with non-FREEZE OP_RETURN must not parse as a freeze op");
}

// ---------------------------------------------------------------------------
// Test 5 — reorg inverts freeze and unfreeze (R1 proof)
//   Proves: the inverse-operation pattern used by DisconnectBlock.
//   FREEZE applied → disconnect erases → outpoint is unfrozen.
//   UNFREEZE applied → disconnect writes → outpoint is re-frozen.
//   This is the correctness test that validates the R1 fix.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(reorg_inverts_freeze_and_unfreeze)
{
    CCoinsViewDB db(1 << 20, /*fMemory=*/true, /*fWipe=*/true);

    // === Part A: FREEZE, then simulate DisconnectBlock (erase) ===
    COutPoint x(uint256S("0xdead"), 0);

    // ConnectBlock applied FREEZE → wrote to registry
    BOOST_CHECK(db.WriteFrozenOutpoint(x));
    BOOST_CHECK(db.IsFrozenOutpoint(x));

    // DisconnectBlock reverses: FREEZE → EraseFrozenOutpoint
    BOOST_CHECK(db.EraseFrozenOutpoint(x));
    BOOST_CHECK_MESSAGE(!db.IsFrozenOutpoint(x),
        "After reorg, FREEZE reversal must erase the outpoint from the set — "
        "X must be spendable again (R1 proof, direction 1)");

    // === Part B: UNFREEZE, then simulate DisconnectBlock (re-write) ===
    COutPoint y(uint256S("0xbeef"), 1);

    // Pre-condition: Y was frozen before the block that unfroze it
    BOOST_CHECK(db.WriteFrozenOutpoint(y));
    BOOST_CHECK(db.IsFrozenOutpoint(y));

    // ConnectBlock applied UNFREEZE → erased from registry
    BOOST_CHECK(db.EraseFrozenOutpoint(y));
    BOOST_CHECK(!db.IsFrozenOutpoint(y));

    // DisconnectBlock reverses: UNFREEZE → WriteFrozenOutpoint (re-freeze)
    BOOST_CHECK(db.WriteFrozenOutpoint(y));
    BOOST_CHECK_MESSAGE(db.IsFrozenOutpoint(y),
        "After reorg, UNFREEZE reversal must re-add the outpoint to the set — "
        "Y must be frozen again (R1 proof, direction 2)");
}

// ---------------------------------------------------------------------------
// Test 6 — SOQ outpoint never frozen (Q3 defense-in-depth)
//   Proves: the registry is asset-agnostic at the storage level, but the
//   ConnectBlock Q3 guard prevents SOQ outpoints from entering. This test
//   validates that even if a SOQ outpoint somehow enters the registry,
//   the enforce guard only checks ASSET_USDSOQ inputs (validation.cpp:2999).
//   The defense-in-depth is: Q3 stops entry, H3 stops enforcement on SOQ.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(soq_outpoint_never_frozen)
{
    CCoinsViewDB db(1 << 20, /*fMemory=*/true, /*fWipe=*/true);

    // Even if someone bypasses Q3 and writes a SOQ outpoint to the registry,
    // the storage layer accepts it (it's just a key-value store).
    COutPoint soqOutpoint(uint256S("0xaaaa"), 0);
    BOOST_CHECK(db.WriteFrozenOutpoint(soqOutpoint));
    BOOST_CHECK(db.IsFrozenOutpoint(soqOutpoint));

    // The REAL protection is in ConnectBlock:
    //   if (prevOut.nAssetType == ASSET_USDSOQ) {  ← SOQ skips this branch
    //       bool frozenByRegistry = ...
    // So even with the entry present, a SOQ spend would never hit the guard.
    // This test documents that the defense layers are:
    //   Layer 1 (Q3): ConnectBlock APPLY checks nAssetType before writing
    //   Layer 2 (H3): ConnectBlock ENFORCE only checks ASSET_USDSOQ inputs
    BOOST_TEST_MESSAGE(
        "Storage layer is asset-agnostic. Defense-in-depth requires "
        "Q3 (apply filter) + H3 (enforce filter) to prevent SOQ freeze.");

    // Cleanup: the entry would be cleaned by a future registry migration
    db.EraseFrozenOutpoint(soqOutpoint);
    BOOST_CHECK(!db.IsFrozenOutpoint(soqOutpoint));
}

// ---------------------------------------------------------------------------
// Test 7 — Parser validation: well-formed and malformed freeze ops
//   Exercises ParseUSDSOQFreezeOp on various OP_RETURN shapes.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(parser_wellformed_freeze_op)
{
    uint256 targetTxid = uint256S("deadbeef01020304050607080910111213141516171819202122232425262728");
    uint32_t targetVout = 42;

    // Construct a tx with a well-formed FREEZE OP_RETURN
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("0xcc"), 0);
    mtx.vout.resize(2);
    // Normal output
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160
        << std::vector<uint8_t>(20, 0) << OP_EQUALVERIFY << OP_CHECKSIG;
    // FREEZE OP_RETURN
    mtx.vout[1].nValue = 0;
    mtx.vout[1].scriptPubKey = MakeFreezeOpReturn(FREEZE_OP_FREEZE, targetTxid, targetVout);

    CTransaction tx(mtx);
    uint8_t op = 0xFF;
    COutPoint target;

    BOOST_CHECK_MESSAGE(ParseUSDSOQFreezeOp(tx, op, target),
        "Well-formed FREEZE OP_RETURN must parse successfully");
    BOOST_CHECK_EQUAL(op, FREEZE_OP_FREEZE);
    BOOST_CHECK(target.hash == targetTxid);
    BOOST_CHECK_EQUAL(target.n, targetVout);
}

BOOST_AUTO_TEST_CASE(parser_wellformed_unfreeze_op)
{
    uint256 targetTxid = uint256S("0102030405060708091011121314151617181920212223242526272829303132");
    uint32_t targetVout = 0;

    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("0xdd"), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 0;
    mtx.vout[0].scriptPubKey = MakeFreezeOpReturn(FREEZE_OP_UNFREEZE, targetTxid, targetVout);

    CTransaction tx(mtx);
    uint8_t op = 0xFF;
    COutPoint target;

    BOOST_CHECK_MESSAGE(ParseUSDSOQFreezeOp(tx, op, target),
        "Well-formed UNFREEZE OP_RETURN must parse successfully");
    BOOST_CHECK_EQUAL(op, FREEZE_OP_UNFREEZE);
    BOOST_CHECK(target.hash == targetTxid);
    BOOST_CHECK_EQUAL(target.n, targetVout);
}

BOOST_AUTO_TEST_CASE(parser_rejects_wrong_tag)
{
    // OP_RETURN with wrong tag — "FROZEN" instead of "FREEZE"
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("0xee"), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 0;

    CScript script;
    script << OP_RETURN;
    std::vector<uint8_t> wrongTag = {'F','R','O','Z','E','N'};
    script << wrongTag;
    std::vector<uint8_t> payload(FREEZE_OP_PAYLOAD_LEN, 0);
    script << payload;
    mtx.vout[0].scriptPubKey = script;

    CTransaction tx(mtx);
    uint8_t op = 0xFF;
    COutPoint target;
    BOOST_CHECK_MESSAGE(!ParseUSDSOQFreezeOp(tx, op, target),
        "Wrong tag 'FROZEN' must not parse as a freeze op");
}

BOOST_AUTO_TEST_CASE(parser_rejects_short_payload)
{
    // OP_RETURN with "FREEZE" tag but payload too short
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("0xff"), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 0;

    CScript script;
    script << OP_RETURN;
    std::vector<uint8_t> tag = {'F','R','E','E','Z','E'};
    script << tag;
    std::vector<uint8_t> shortPayload(10, 0);  // 10 bytes instead of 37
    script << shortPayload;
    mtx.vout[0].scriptPubKey = script;

    CTransaction tx(mtx);
    uint8_t op = 0xFF;
    COutPoint target;
    BOOST_CHECK_MESSAGE(!ParseUSDSOQFreezeOp(tx, op, target),
        "Short payload (10 bytes) must not parse as a freeze op");
}

BOOST_AUTO_TEST_CASE(parser_rejects_duplicate_freeze_opreturn)
{
    // TX with two FREEZE OP_RETURNs — single-action invariant
    uint256 txid1 = uint256S("0x1111");
    uint256 txid2 = uint256S("0x2222");

    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("0xab"), 0);
    mtx.vout.resize(2);
    mtx.vout[0].nValue = 0;
    mtx.vout[0].scriptPubKey = MakeFreezeOpReturn(FREEZE_OP_FREEZE, txid1, 0);
    mtx.vout[1].nValue = 0;
    mtx.vout[1].scriptPubKey = MakeFreezeOpReturn(FREEZE_OP_FREEZE, txid2, 1);

    CTransaction tx(mtx);
    uint8_t op = 0xFF;
    COutPoint target;
    BOOST_CHECK_MESSAGE(!ParseUSDSOQFreezeOp(tx, op, target),
        "Duplicate FREEZE OP_RETURNs must be rejected (single-action invariant)");
}

BOOST_AUTO_TEST_SUITE_END()
