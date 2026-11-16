// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bech32.h"
#include "chainparams.h"
#include "rpc/server.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "utiladdress.h"
#include "utilstrencodings.h"
#include "wallet/pqwallet/pqaddress.h"
#include "wallet/pqwallet/rpc_pqwallet.h"

#include <array>
#include <string>
#include <utility>
#include <vector>

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>

BOOST_FIXTURE_TEST_SUITE(pqwallet_rpc_tests, BasicTestingSetup)

static UniValue PQValidateAddress(const std::string& address)
{
    CRPCTable table;
    RegisterPQWalletRPCCommands(table);
    JSONRPCRequest request;
    request.strMethod = "pqvalidateaddress";
    request.params = UniValue(UniValue::VARR);
    request.params.push_back(address);
    return table["pqvalidateaddress"]->actor(request);
}

static bool IsValid(const std::string& address)
{
    return find_value(PQValidateAddress(address), "isvalid").get_bool();
}

// 8-bit bytes to padded 5-bit groups, the bech32 data layout.
static std::vector<uint8_t> FiveBit(const std::vector<uint8_t>& bytes)
{
    std::vector<uint8_t> groups;
    uint32_t acc = 0;
    int bits = 0;
    for (uint8_t byte : bytes) {
        acc = ((acc << 8) | byte) & 0xfff;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            groups.push_back((acc >> bits) & 31);
        }
    }
    if (bits) groups.push_back((acc << (5 - bits)) & 31);
    return groups;
}

// The node's layout: the witness version is a 5-bit group of its own, followed by the program.
static std::vector<uint8_t> WitnessData(uint8_t version, const std::vector<uint8_t>& program)
{
    std::vector<uint8_t> data{version};
    const std::vector<uint8_t> groups = FiveBit(program);
    data.insert(data.end(), groups.begin(), groups.end());
    return data;
}

BOOST_AUTO_TEST_CASE(pqvalidateaddress_decodes_with_the_network_prefix)
{
    const std::string fixture_network = Params().NetworkIDString();
    const WitnessV1ScriptHash program(uint256S("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"));
    const std::vector<uint8_t> bytes(program.begin(), program.end());
    const std::vector<std::pair<std::string, std::string> > networks{
        {CBaseChainParams::MAIN, "mainnet"},
        {CBaseChainParams::TESTNET, "testnet"},
        {CBaseChainParams::STAGENET, "stagenet"},
        {CBaseChainParams::REGTEST, "regtest"},
    };

    for (const auto& network : networks) {
        SelectParams(network.first);
        const std::string hrp = Params().Bech32HRP();

        // The node's own encoding: valid, with the program as pubkey_hash.
        const std::string address = EncodeDestination(program, hrp);
        BOOST_CHECK_EQUAL(address, bech32::Encode(bech32::Encoding::BECH32M, hrp, WitnessData(1, bytes)));
        const UniValue valid = PQValidateAddress(address);
        BOOST_CHECK(find_value(valid, "isvalid").get_bool());
        BOOST_CHECK_EQUAL(find_value(valid, "network").getValStr(), network.second);
        BOOST_CHECK_EQUAL(find_value(valid, "pubkey_hash").getValStr(), HexStr(bytes));
        BOOST_CHECK_EQUAL(find_value(valid, "type").getValStr(), "P2PQ");
        BOOST_CHECK(find_value(valid, "error").isNull());

        // Upper case decodes to the same program; bech32::Decode refuses mixed case.
        const UniValue upper = PQValidateAddress(boost::to_upper_copy(address));
        BOOST_CHECK(find_value(upper, "isvalid").get_bool());
        BOOST_CHECK_EQUAL(find_value(upper, "pubkey_hash").getValStr(), HexStr(bytes));
        std::string mixed_case = address;
        mixed_case[0] = 'S';
        BOOST_CHECK(!IsValid(mixed_case));

        // The layout pqgetnewaddress returned: the version byte converted with the program, so the first group
        // reads as witness version 0 under a bech32m checksum.
        std::vector<uint8_t> versioned{1};
        versioned.insert(versioned.end(), bytes.begin(), bytes.end());
        const std::string old_layout = bech32::Encode(bech32::Encoding::BECH32M, hrp, FiveBit(versioned));
        BOOST_CHECK_EQUAL(old_layout.substr(hrp.size(), 2), "1q");
        const UniValue refused = PQValidateAddress(old_layout);
        BOOST_CHECK(!find_value(refused, "isvalid").get_bool());
        BOOST_CHECK_EQUAL(find_value(refused, "error").getValStr(), "Invalid address format");
        BOOST_CHECK(find_value(refused, "pubkey_hash").isNull());
        BOOST_CHECK(find_value(refused, "network").isNull());

        // Another network's prefix, and tsq, which no network uses.
        BOOST_CHECK(!IsValid(EncodeDestination(program, hrp == "ssq" ? "sq" : "ssq")));
        BOOST_CHECK(!IsValid(EncodeDestination(program, "tsq")));

        // Witness versions 0 and 2, programs of 20 and 33 bytes, the bech32 checksum.
        BOOST_CHECK(!IsValid(bech32::Encode(bech32::Encoding::BECH32M, hrp, WitnessData(0, bytes))));
        BOOST_CHECK(!IsValid(bech32::Encode(bech32::Encoding::BECH32M, hrp, WitnessData(2, bytes))));
        const std::vector<uint8_t> short_program(bytes.begin(), bytes.begin() + 20);
        BOOST_CHECK(!IsValid(bech32::Encode(bech32::Encoding::BECH32M, hrp, WitnessData(1, short_program))));
        std::vector<uint8_t> long_program(bytes);
        long_program.push_back(0);
        BOOST_CHECK(!IsValid(bech32::Encode(bech32::Encoding::BECH32M, hrp, WitnessData(1, long_program))));
        BOOST_CHECK(!IsValid(bech32::Encode(bech32::Encoding::BECH32, hrp, WitnessData(1, bytes))));
    }
    SelectParams(fixture_network);
}

BOOST_AUTO_TEST_CASE(pqgetnewaddress_is_not_registered)
{
    CRPCTable table;
    RegisterPQWalletRPCCommands(table);
    BOOST_CHECK(table["pqgetnewaddress"] == nullptr);
    BOOST_CHECK(table["pqvalidateaddress"] != nullptr);
}

// PQAddress::EncodeFromHash packs the version byte and the 32-byte hash into
// 5-bit groups. This is the library's own layout, which the node refuses as an
// address (the case pqvalidateaddress_decodes_with_the_network_prefix above).
// The case pins that output, so that a change to the loop shows. The expected
// strings are bech32m over the 53 groups of 0x01 || hash, from the BIP 350
// reference encoder, so they do not depend on this tree's bit conversion.
BOOST_AUTO_TEST_CASE(encode_from_hash_keeps_the_library_layout)
{
    using soqucoin::pqwallet::AddressType;
    using soqucoin::pqwallet::Network;
    using soqucoin::pqwallet::PQAddress;

    std::array<uint8_t, 32> zeros;
    zeros.fill(0x00);
    BOOST_CHECK_EQUAL(PQAddress::EncodeFromHash(zeros, Network::Mainnet, AddressType::P2PQ),
        "sq1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq897wn3");

    std::array<uint8_t, 32> ones;
    ones.fill(0xff);
    BOOST_CHECK_EQUAL(PQAddress::EncodeFromHash(ones, Network::Testnet, AddressType::P2PQ),
        "tsq1q8llllllllllllllllllllllllllllllllllllllllllllllllll7jkc7qa");

    std::array<uint8_t, 32> counting;
    for (size_t i = 0; i < counting.size(); i++) counting[i] = static_cast<uint8_t>(i);
    BOOST_CHECK_EQUAL(PQAddress::EncodeFromHash(counting, Network::Stagenet, AddressType::P2PQ_PAT),
        "ssqp1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7ekpah9");
}

BOOST_AUTO_TEST_SUITE_END()
