// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"
#include "test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(key_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(key_dilithium_sanity)
{
    CKey key;
    key.MakeNewKey(true);
    BOOST_CHECK(key.IsValid());
    
    CPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(pubkey.IsValid());
    BOOST_CHECK(pubkey.size() == 1312 || pubkey.size() == 1313); // ML-DSA-44 size

    uint256 hash = uint256S("0x000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");
    std::vector<unsigned char> vchSig;
    BOOST_CHECK(key.Sign(hash, vchSig));
    BOOST_CHECK(pubkey.Verify(hash, vchSig));
}

BOOST_AUTO_TEST_SUITE_END()
