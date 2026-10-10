// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The seed bound of the HKDF derivation library (pqderive.h, MIN_SEED_BYTES):
// a seed shorter than the bound derives nothing, at and above the bound every
// function derives, and the known answers for the 64-byte BIP-39 seed are
// unchanged by the bound.

#include "test/test_bitcoin.h"
#include "utilstrencodings.h"
#include "wallet/pqwallet/pqderive.h"
#include "wallet/pqwallet/pqkeys.h"

#include <algorithm>
#include <array>
#include <stdexcept>

#include <boost/test/unit_test.hpp>

using namespace soqucoin::pqwallet;

namespace {

// The BIP-39 seed of the mnemonic "abandon abandon ... about", the seed
// test/pqderive-test --json-vectors derives its published vectors from.
const uint8_t kSeed64[64] = {
    0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08,
    0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56, 0x81,
    0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70,
    0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda, 0x5f, 0xc1,
    0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70,
    0xd0, 0x86, 0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4,
    0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
    0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4};

//! The first n bytes of the 64-byte seed.
SecureBytes Seed(size_t n)
{
    return SecureBytes(kSeed64, n);
}

//! m/44'/21329'/0'/0/0, the wallet's first external key.
DerivationPath Path0()
{
    DerivationPath p;
    p.purpose = 44;
    p.coinType = 21329;
    p.account = 0;
    p.change = 0;
    p.index = 0;
    return p;
}

bool AllZero(const std::array<uint8_t, 32>& a)
{
    return std::all_of(a.begin(), a.end(), [](uint8_t b) { return b == 0; });
}

std::string Hex(const std::array<uint8_t, 32>& a)
{
    return HexStr(a.begin(), a.end());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pqderive_seed_tests, BasicTestingSetup)

// Below the bound nothing is derived: every derivation function throws before
// touching the seed, and DeriveFromSeed returns its documented failure value.
BOOST_AUTO_TEST_CASE(short_seed_derives_nothing)
{
    BOOST_CHECK_EQUAL(MIN_SEED_BYTES, 32u);
    for (size_t n : {size_t(0), size_t(1), size_t(16), size_t(31)}) {
        const SecureBytes seed = Seed(n);
        BOOST_CHECK_THROW(DeriveKeyMaterial(seed, Path0(), DOMAIN_WALLET), std::invalid_argument);
        BOOST_CHECK_THROW(DeriveKeyMaterial(seed, Path0(), DOMAIN_WALLET, 1), std::invalid_argument);
        BOOST_CHECK_THROW(DeriveKeyMaterial(seed, Path0(), DOMAIN_BLINDING), std::invalid_argument);
        BOOST_CHECK_THROW(DeriveBlindingFactor(seed, 0), std::invalid_argument);
        BOOST_CHECK_THROW(DeriveBlindingFactor(seed, uint64_t(1) << 40), std::invalid_argument);
        BOOST_CHECK_THROW(DeriveChannelKey(seed, "test-channel-001", "funding", 0), std::invalid_argument);
        BOOST_CHECK_THROW(DeriveChannelKey(seed, "test-channel-001", "revoke", 3), std::invalid_argument);
        BOOST_CHECK(PQKeyPair::DeriveFromSeed(seed, Path0()) == nullptr);
    }
}

// At the bound and above every function derives: no all-zero material, the
// domains separate, and DeriveFromSeed gives one valid, deterministic key pair.
BOOST_AUTO_TEST_CASE(seed_at_the_bound_derives)
{
    for (size_t n : {size_t(32), size_t(33), size_t(64)}) {
        const SecureBytes seed = Seed(n);
        const std::array<uint8_t, 32> wallet = DeriveKeyMaterial(seed, Path0(), DOMAIN_WALLET);
        const std::array<uint8_t, 32> blinding = DeriveKeyMaterial(seed, Path0(), DOMAIN_BLINDING);
        const std::array<uint8_t, 32> factor = DeriveBlindingFactor(seed, 0);
        const std::array<uint8_t, 32> channel = DeriveChannelKey(seed, "test-channel-001", "funding", 0);
        BOOST_CHECK(!AllZero(wallet));
        BOOST_CHECK(!AllZero(blinding));
        BOOST_CHECK(!AllZero(factor));
        BOOST_CHECK(!AllZero(channel));
        BOOST_CHECK(wallet != blinding);
        BOOST_CHECK(wallet != factor);
        BOOST_CHECK(wallet != channel);

        std::unique_ptr<PQKeyPair> first = PQKeyPair::DeriveFromSeed(seed, Path0());
        BOOST_REQUIRE(first != nullptr);
        BOOST_CHECK(first->GetPublicKey()[0] != 0xFF);
        std::unique_ptr<PQKeyPair> again = PQKeyPair::DeriveFromSeed(seed, Path0());
        BOOST_REQUIRE(again != nullptr);
        BOOST_CHECK(first->GetPublicKey() == again->GetPublicKey());
    }
}

// The known answers of test/pqderive-test --json-vectors for the 64-byte seed:
// the bound changes nothing for a seed it accepts.
BOOST_AUTO_TEST_CASE(known_answers_unchanged)
{
    const SecureBytes seed = Seed(64);
    BOOST_CHECK_EQUAL(Hex(DeriveKeyMaterial(seed, Path0(), DOMAIN_WALLET)), "bb30b7462d21c41a40999091791974e5f1275d4d39f2958fccb8c88cc0d6fa87");
    BOOST_CHECK_EQUAL(Hex(DeriveBlindingFactor(seed, 0)), "863885c6376a027824964be05f9cdbfbf2f10654ffe60ebe1158651b31d75c76");
    BOOST_CHECK_EQUAL(Hex(DeriveChannelKey(seed, "test-channel-001", "funding", 0)), "9fb62d9cb04870ede03b2d740e118d3551bab40f0e1b1bef565711e220ea6fc5");
}

BOOST_AUTO_TEST_SUITE_END()
