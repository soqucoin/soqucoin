// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// BTCSOQ consensus module tests. Covers the supply counter, the M-of-N
// Dilithium authority, and the Bitcoin-deposit-bound MINT payload plus the
// minted-outpoint anti-replay key. Chainstate/ConnectBlock integration is
// tested separately once wired (see DL-BTCSOQ-CONSENSUS-NATIVE.md).

#include "consensus/btcsoq.h"
#include "amount.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(btcsoq_tests, BasicTestingSetup)

// ---- supply counter ----
BOOST_AUTO_TEST_CASE(supply_mint_burn_invariant)
{
    CBTCSOQSupply s;
    BOOST_CHECK(s.CheckInvariant());
    BOOST_CHECK_EQUAL(s.Outstanding(), 0);

    BOOST_CHECK(s.Mint(100 * COIN));
    BOOST_CHECK_EQUAL(s.Outstanding(), 100 * COIN);
    BOOST_CHECK(s.CheckInvariant());

    // cannot burn more than outstanding
    BOOST_CHECK(!s.Burn(101 * COIN));
    BOOST_CHECK(s.Burn(40 * COIN));
    BOOST_CHECK_EQUAL(s.Outstanding(), 60 * COIN);

    // non-positive amounts rejected
    BOOST_CHECK(!s.Mint(0));
    BOOST_CHECK(!s.Mint(-1));
    BOOST_CHECK(!s.Burn(0));

    // out-of-range mint rejected, counter unchanged
    BOOST_CHECK(!s.Mint(MAX_MONEY + 1));
    BOOST_CHECK_EQUAL(s.Outstanding(), 60 * COIN);
    BOOST_CHECK(s.CheckInvariant());
}

BOOST_AUTO_TEST_CASE(supply_undo_symmetry)
{
    CBTCSOQSupply s;
    BOOST_CHECK(s.Mint(50 * COIN));
    BOOST_CHECK(s.Burn(20 * COIN));
    // reorg reverses in the opposite order
    BOOST_CHECK(s.UndoBurn(20 * COIN));
    BOOST_CHECK_EQUAL(s.Outstanding(), 50 * COIN);
    BOOST_CHECK(s.UndoMint(50 * COIN));
    BOOST_CHECK_EQUAL(s.Outstanding(), 0);
    BOOST_CHECK_EQUAL(s.TotalMinted(), 0);
    // cannot undo beyond recorded totals
    BOOST_CHECK(!s.UndoMint(1));
    BOOST_CHECK(!s.UndoBurn(1));
}

// ---- authority ----
BOOST_AUTO_TEST_CASE(authority_init_rules)
{
    CBTCSOQAuthority a;
    BOOST_CHECK(!a.IsInitialized());

    std::vector<std::vector<uint8_t>> keys = {
        std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, 0x01),
        std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, 0x02),
        std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, 0x03),
    };
    // threshold below minimum rejected
    BOOST_CHECK(!a.Initialize(keys, 1));
    // threshold above key count rejected
    BOOST_CHECK(!a.Initialize(keys, 4));
    // wrong key size rejected
    std::vector<std::vector<uint8_t>> badsize = {std::vector<uint8_t>(10, 0x01),
                                                 std::vector<uint8_t>(10, 0x02)};
    BOOST_CHECK(!a.Initialize(badsize, 2));
    // duplicate keys rejected
    std::vector<std::vector<uint8_t>> dup = {
        std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, 0x07),
        std::vector<uint8_t>(DILITHIUM_PUBKEY_SIZE, 0x07)};
    BOOST_CHECK(!a.Initialize(dup, 2));
    // valid 2-of-3
    BOOST_CHECK(a.Initialize(keys, 2));
    BOOST_CHECK(a.IsInitialized());
    BOOST_CHECK_EQUAL(a.GetThreshold(), 2u);
    BOOST_CHECK_EQUAL(a.GetKeyCount(), 3u);
    // signatures of wrong size rejected without crashing
    std::vector<std::vector<uint8_t>> badsigs = {std::vector<uint8_t>(10, 0x00)};
    BOOST_CHECK(!a.VerifyAuthoritySignatures(std::vector<uint8_t>(32, 0xaa), badsigs));
}

// ---- MINT payload ----
BOOST_AUTO_TEST_CASE(mint_payload_roundtrip)
{
    uint256 txid = uint256S("deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb");
    uint256 recip = uint256S("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    CAmount sats = 50LL * 100000000LL;  // 50 BTC in sats

    std::vector<uint8_t> p = BuildBTCSOQMintPayload(txid, 7, sats, recip);
    BOOST_CHECK_EQUAL(p.size(), BTCSOQ_MINT_PAYLOAD_LEN);

    uint256 t2, r2; uint32_t vo2; CAmount s2;
    BOOST_CHECK(ParseBTCSOQMintPayload(p, t2, vo2, s2, r2));
    BOOST_CHECK(t2 == txid);
    BOOST_CHECK(r2 == recip);
    BOOST_CHECK_EQUAL(vo2, 7u);
    BOOST_CHECK_EQUAL(s2, sats);
}

BOOST_AUTO_TEST_CASE(mint_payload_rejects_malformed)
{
    uint256 txid, recip;
    uint256 t2, r2; uint32_t vo2; CAmount s2;

    // wrong length
    std::vector<uint8_t> short_p(BTCSOQ_MINT_PAYLOAD_LEN - 1, 0x00);
    BOOST_CHECK(!ParseBTCSOQMintPayload(short_p, t2, vo2, s2, r2));

    // zero sats
    std::vector<uint8_t> zero = BuildBTCSOQMintPayload(txid, 0, 0, recip);
    BOOST_CHECK(!ParseBTCSOQMintPayload(zero, t2, vo2, s2, r2));

    // above 21M BTC supply (all-0xff sats field)
    std::vector<uint8_t> over = BuildBTCSOQMintPayload(txid, 0, 1, recip);
    for (int i = 0; i < 8; ++i) over[36 + i] = 0xff;
    BOOST_CHECK(!ParseBTCSOQMintPayload(over, t2, vo2, s2, r2));
}

// ---- anti-replay outpoint key ----
BOOST_AUTO_TEST_CASE(minted_outpoint_key_is_deterministic_and_distinct)
{
    uint256 txid = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    std::vector<uint8_t> k0 = BTCSOQMintedOutpointKey(txid, 0);
    std::vector<uint8_t> k0b = BTCSOQMintedOutpointKey(txid, 0);
    std::vector<uint8_t> k1 = BTCSOQMintedOutpointKey(txid, 1);
    BOOST_CHECK_EQUAL(k0.size(), 36u);
    BOOST_CHECK(k0 == k0b);   // deterministic
    BOOST_CHECK(!(k0 == k1)); // different vout -> different key
}

// ---- BURN payload ----
BOOST_AUTO_TEST_CASE(burn_payload_roundtrip_and_rejects)
{
    uint256 release = uint256S("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    CAmount sats = 15000;

    std::vector<uint8_t> p = BuildBTCSOQBurnPayload(release, sats);
    BOOST_CHECK_EQUAL(p.size(), BTCSOQ_BURN_PAYLOAD_LEN);

    uint256 r2; CAmount s2;
    BOOST_CHECK(ParseBTCSOQBurnPayload(p, r2, s2));
    BOOST_CHECK(r2 == release);
    BOOST_CHECK_EQUAL(s2, sats);

    // wrong length
    std::vector<uint8_t> short_p(BTCSOQ_BURN_PAYLOAD_LEN - 1, 0x00);
    BOOST_CHECK(!ParseBTCSOQBurnPayload(short_p, r2, s2));

    // zero sats
    std::vector<uint8_t> zero = BuildBTCSOQBurnPayload(release, 0);
    BOOST_CHECK(!ParseBTCSOQBurnPayload(zero, r2, s2));

    // above 21M BTC in sats
    std::vector<uint8_t> over = BuildBTCSOQBurnPayload(release, 1);
    for (int i = 0; i < 8; ++i) over[32 + i] = 0xff;
    BOOST_CHECK(!ParseBTCSOQBurnPayload(over, r2, s2));
}

// ---- signed OP_RETURN op envelope ----
static CScript MakeBTCSOQOpReturn(uint8_t tag, size_t payloadLen, uint8_t fill = 0x11)
{
    std::vector<unsigned char> data;
    data.push_back(tag);
    data.insert(data.end(), payloadLen, fill);
    return CScript() << OP_RETURN << data;
}

BOOST_AUTO_TEST_CASE(authority_op_envelope_parses_each_op)
{
    uint8_t tag = 0;
    std::vector<uint8_t> payload;

    // MINT (76-byte payload)
    {
        CMutableTransaction mtx;
        mtx.vout.emplace_back(0, MakeBTCSOQOpReturn(BTCSOQ_OP_MINT, BTCSOQ_MINT_PAYLOAD_LEN));
        BOOST_CHECK(ParseBTCSOQAuthorityOp(CTransaction(mtx), tag, payload));
        BOOST_CHECK_EQUAL(tag, BTCSOQ_OP_MINT);
        BOOST_CHECK_EQUAL(payload.size(), BTCSOQ_MINT_PAYLOAD_LEN);
    }
    // BURN (40-byte payload)
    {
        CMutableTransaction mtx;
        mtx.vout.emplace_back(0, MakeBTCSOQOpReturn(BTCSOQ_OP_BURN, BTCSOQ_BURN_PAYLOAD_LEN));
        BOOST_CHECK(ParseBTCSOQAuthorityOp(CTransaction(mtx), tag, payload));
        BOOST_CHECK_EQUAL(tag, BTCSOQ_OP_BURN);
        BOOST_CHECK_EQUAL(payload.size(), BTCSOQ_BURN_PAYLOAD_LEN);
    }
    // FREEZE (37-byte payload, USDSOQ freeze layout inside the envelope)
    {
        CMutableTransaction mtx;
        mtx.vout.emplace_back(0, MakeBTCSOQOpReturn(BTCSOQ_OP_FREEZE, FREEZE_OP_PAYLOAD_LEN));
        BOOST_CHECK(ParseBTCSOQAuthorityOp(CTransaction(mtx), tag, payload));
        BOOST_CHECK_EQUAL(tag, BTCSOQ_OP_FREEZE);
        BOOST_CHECK_EQUAL(payload.size(), FREEZE_OP_PAYLOAD_LEN);
    }
}

BOOST_AUTO_TEST_CASE(authority_op_envelope_rejects)
{
    uint8_t tag = 0;
    std::vector<uint8_t> payload;

    // ROTATE (0x62) has no wired semantics — must not be recognized
    {
        CMutableTransaction mtx;
        mtx.vout.emplace_back(0, MakeBTCSOQOpReturn(BTCSOQ_OP_ROTATE, 76));
        BOOST_CHECK(!ParseBTCSOQAuthorityOp(CTransaction(mtx), tag, payload));
    }
    // wrong payload length for the tag
    {
        CMutableTransaction mtx;
        mtx.vout.emplace_back(0, MakeBTCSOQOpReturn(BTCSOQ_OP_MINT, BTCSOQ_MINT_PAYLOAD_LEN - 1));
        BOOST_CHECK(!ParseBTCSOQAuthorityOp(CTransaction(mtx), tag, payload));
    }
    // unknown tag byte
    {
        CMutableTransaction mtx;
        mtx.vout.emplace_back(0, MakeBTCSOQOpReturn(0x7f, BTCSOQ_MINT_PAYLOAD_LEN));
        BOOST_CHECK(!ParseBTCSOQAuthorityOp(CTransaction(mtx), tag, payload));
    }
    // two well-formed ops in one tx — single-action invariant fails the parse
    {
        CMutableTransaction mtx;
        mtx.vout.emplace_back(0, MakeBTCSOQOpReturn(BTCSOQ_OP_MINT, BTCSOQ_MINT_PAYLOAD_LEN));
        mtx.vout.emplace_back(0, MakeBTCSOQOpReturn(BTCSOQ_OP_BURN, BTCSOQ_BURN_PAYLOAD_LEN));
        BOOST_CHECK(!ParseBTCSOQAuthorityOp(CTransaction(mtx), tag, payload));
    }
    // trailing push after the payload — strict envelope rejects
    {
        std::vector<unsigned char> data;
        data.push_back(BTCSOQ_OP_BURN);
        data.insert(data.end(), BTCSOQ_BURN_PAYLOAD_LEN, 0x22);
        CScript withTrailer = CScript() << OP_RETURN << data
                                        << std::vector<unsigned char>{0x01};
        CMutableTransaction mtx;
        mtx.vout.emplace_back(0, withTrailer);
        BOOST_CHECK(!ParseBTCSOQAuthorityOp(CTransaction(mtx), tag, payload));
    }
    // a non-OP_RETURN output alongside a valid op does not disturb the parse
    {
        CMutableTransaction mtx;
        mtx.vout.emplace_back(1000, CScript() << OP_TRUE);
        mtx.vout.emplace_back(0, MakeBTCSOQOpReturn(BTCSOQ_OP_BURN, BTCSOQ_BURN_PAYLOAD_LEN));
        BOOST_CHECK(ParseBTCSOQAuthorityOp(CTransaction(mtx), tag, payload));
        BOOST_CHECK_EQUAL(tag, BTCSOQ_OP_BURN);
    }
}

// ---- Step 2D: script-layer classification, policy, and dispatch gating ----

static CScript WitnessScript(opcodetype version, uint8_t fill)
{
    return CScript() << version << std::vector<unsigned char>(32, fill);
}

BOOST_AUTO_TEST_CASE(solver_classifies_v8_and_v9)
{
    txnouttype whichType;
    std::vector<std::vector<unsigned char>> vSolutions;

    BOOST_CHECK(Solver(WitnessScript(OP_8, 0xaa), whichType, vSolutions));
    BOOST_CHECK(whichType == TX_WITNESS_V8_BTCSOQ);

    BOOST_CHECK(Solver(WitnessScript(OP_9, 0xbb), whichType, vSolutions));
    BOOST_CHECK(whichType == TX_WITNESS_V9_BTCSOQ_AUTHORITY);

    // v10 remains unrecognized (future witness)
    BOOST_CHECK(!Solver(WitnessScript(OP_10, 0xcc), whichType, vSolutions));
}

BOOST_AUTO_TEST_CASE(policy_accepts_v8_v9_rejects_v10)
{
    txnouttype whichType;
    BOOST_CHECK(::IsStandard(WitnessScript(OP_8, 0x01), whichType, true));
    BOOST_CHECK(whichType == TX_WITNESS_V8_BTCSOQ);
    BOOST_CHECK(::IsStandard(WitnessScript(OP_9, 0x02), whichType, true));
    BOOST_CHECK(whichType == TX_WITNESS_V9_BTCSOQ_AUTHORITY);
    // Future witness versions stay policy-rejected until their soft fork.
    BOOST_CHECK(!::IsStandard(WitnessScript(OP_10, 0x03), whichType, true));
}

BOOST_AUTO_TEST_CASE(verifyscript_gates_v8_and_v9)
{
    ScriptError err = SCRIPT_ERR_OK;
    BaseSignatureChecker checker;
    CScriptWitness wit;
    wit.stack.push_back({0x01});  // arbitrary junk witness

    // v9 marker: pre-activation = anyone-can-spend (soft-fork safe)
    BOOST_CHECK(VerifyScript(CScript(), WitnessScript(OP_9, 0x11), &wit, 0, checker, &err));

    // v9 marker: active = default-deny (authority txs never reach VerifyScript,
    // so any evaluated v9 spend is a non-authority marker theft attempt)
    BOOST_CHECK(!VerifyScript(CScript(), WitnessScript(OP_9, 0x11), &wit,
                              SCRIPT_VERIFY_BTCSOQ, checker, &err));
    BOOST_CHECK(err == SCRIPT_ERR_BTCSOQ_MARKER_SPEND);

    // v8 holding: pre-activation = anyone-can-spend
    BOOST_CHECK(VerifyScript(CScript(), WitnessScript(OP_8, 0x22), &wit, 0, checker, &err));

    // v8 holding: active = requires the v1 Dilithium witness shape
    // ([sig, pubkey]); a junk 1-item witness must fail structurally.
    BOOST_CHECK(!VerifyScript(CScript(), WitnessScript(OP_8, 0x22), &wit,
                              SCRIPT_VERIFY_BTCSOQ, checker, &err));
    BOOST_CHECK(err == SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);

    // v8 active with the right shape but wrong pubkey (hash mismatch) fails.
    CScriptWitness wit2;
    wit2.stack.push_back(std::vector<unsigned char>(2421, 0x00));  // sig-sized junk
    wit2.stack.push_back(std::vector<unsigned char>(1313, 0x00));  // 0x00-prefixed pubkey-sized junk
    BOOST_CHECK(!VerifyScript(CScript(), WitnessScript(OP_8, 0x22), &wit2,
                              SCRIPT_VERIFY_BTCSOQ, checker, &err));
    BOOST_CHECK(err == SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
}

// ---- witness tag strictness ----
BOOST_AUTO_TEST_CASE(witness_tag_requires_exactly_one_byte)
{
    // The tag item must be exactly 1 byte: the CheckInputs authority skip
    // requires size()==1, so the consensus-side reader must agree or an
    // unsigned-witness malleation could desync the two (2D review finding).
    std::vector<std::vector<uint8_t>> stack(6);
    stack[2] = {BTCSOQ_OP_MINT};
    BOOST_CHECK_EQUAL(GetBTCSOQWitnessTag(stack), BTCSOQ_OP_MINT);

    stack[2] = {BTCSOQ_OP_MINT, 0x00};  // padded tag — must NOT parse
    BOOST_CHECK_EQUAL(GetBTCSOQWitnessTag(stack), 0x00);

    stack[2].clear();                   // empty tag item
    BOOST_CHECK_EQUAL(GetBTCSOQWitnessTag(stack), 0x00);

    std::vector<std::vector<uint8_t>> shortStack(2);
    BOOST_CHECK_EQUAL(GetBTCSOQWitnessTag(shortStack), 0x00);
}

// ---- recipient commitment ----
BOOST_AUTO_TEST_CASE(recipient_commitment_binds_exact_script)
{
    CScript a = CScript() << OP_8 << std::vector<unsigned char>(32, 0xaa);
    CScript b = CScript() << OP_8 << std::vector<unsigned char>(32, 0xab);

    uint256 ca = ComputeBTCSOQRecipientCommitment(a);
    BOOST_CHECK(ca == ComputeBTCSOQRecipientCommitment(a));  // deterministic
    BOOST_CHECK(ca != ComputeBTCSOQRecipientCommitment(b));  // any script change breaks it
    BOOST_CHECK(!ca.IsNull());
}

BOOST_AUTO_TEST_SUITE_END()
