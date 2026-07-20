// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// BTCSOQ consensus module tests. Covers the supply counter, the M-of-N
// Dilithium authority, and the Bitcoin-deposit-bound MINT payload plus the
// minted-outpoint anti-replay key. Chainstate/ConnectBlock integration is
// tested separately once wired (see DL-BTCSOQ-CONSENSUS-NATIVE.md).

#include "consensus/btcsoq.h"
#include "amount.h"
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

BOOST_AUTO_TEST_SUITE_END()
