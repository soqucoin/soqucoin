// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// witness_v6_address_tests.cpp — the address form of a witness version 6
// output, and the raw transaction RPCs that read or print an address.
//
// The vectors are test/data/witness_address_vectors.json: per network prefix,
// programs with their version 1 and version 6 addresses, and strings a decoder
// must refuse, each with the first check it fails. Codecs outside this tree
// read the same file, so it carries no script bytes: every script here is
// built from the vector's program.
//
// Covered:
//   * the file: its network map against chainparams, every valid string
//     rebuilt with bech32::Encode and a bit conversion written here, every
//     invalid string's reason recomputed here;
//   * version 1: EncodeDestination and DecodeDestination on every vector, and
//     DecodeDestination, validateaddress and createrawtransaction refusing
//     every version 6 address;
//   * version 6: EncodeWitnessV6Address and DecodeWitnessV6Address;
//   * createrawtransaction: the bytes it builds without the version argument,
//     and the version argument;
//   * decodescript, decoderawtransaction and gettxout printing the address of
//     a version 6 output, the last two for an output mined in a regtest block.

#include "base58.h"
#include "bech32.h"
#include "chainparams.h"
#include "core_io.h"
#include "primitives/transaction.h"
#include "rpc/client.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/dilithium_chain_setup.h"
#include "test/test_bitcoin.h"
#include "utiladdress.h"
#include "utilstrencodings.h"

#include "data/witness_address_vectors.json.h"

#include <boost/test/unit_test.hpp>
#include <univalue.h>

#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

struct ValidVector {
    std::string prefix;
    int version;
    std::vector<unsigned char> program;
    std::string address;
};

struct InvalidVector {
    std::string prefix;
    int version;
    std::string address;
    std::string reason;
};

struct VectorFile {
    std::map<std::string, std::string> networks; //!< network name to prefix
    std::vector<ValidVector> valid;
    std::vector<InvalidVector> invalid;
};

VectorFile LoadVectors()
{
    UniValue root;
    BOOST_REQUIRE(root.read(std::string(json_tests::witness_address_vectors,
        json_tests::witness_address_vectors + sizeof(json_tests::witness_address_vectors))));
    BOOST_REQUIRE(root.isObject());

    VectorFile file;
    const UniValue& networks = find_value(root, "networks");
    BOOST_REQUIRE(networks.isObject());
    for (const std::string& name : networks.getKeys())
        file.networks[name] = networks[name].get_str();

    const UniValue& valid = find_value(root, "valid");
    BOOST_REQUIRE(valid.isArray());
    for (size_t i = 0; i < valid.size(); ++i) {
        ValidVector v;
        v.prefix = find_value(valid[i], "prefix").get_str();
        v.version = find_value(valid[i], "version").get_int();
        const std::string hex = find_value(valid[i], "program").get_str();
        BOOST_REQUIRE_MESSAGE(IsHex(hex), "program is not hex: " + hex);
        v.program = ParseHex(hex);
        v.address = find_value(valid[i], "address").get_str();
        file.valid.push_back(v);
    }

    const UniValue& invalid = find_value(root, "invalid");
    BOOST_REQUIRE(invalid.isArray());
    for (size_t i = 0; i < invalid.size(); ++i) {
        InvalidVector v;
        v.prefix = find_value(invalid[i], "prefix").get_str();
        v.version = find_value(invalid[i], "version").get_int();
        v.address = find_value(invalid[i], "address").get_str();
        v.reason = find_value(invalid[i], "reason").get_str();
        file.invalid.push_back(v);
    }
    return file;
}

//! The networks this node can select.
std::vector<std::string> NodeNetworks()
{
    return {CBaseChainParams::MAIN, CBaseChainParams::TESTNET, CBaseChainParams::STAGENET, CBaseChainParams::REGTEST};
}

//! Select a network for a scope; the fixtures run on regtest and get it back.
struct NetworkScope {
    explicit NetworkScope(const std::string& network) { SelectParams(network); }
    ~NetworkScope() { SelectParams(CBaseChainParams::REGTEST); }
};

std::string Upper(const std::string& str)
{
    std::string out(str);
    for (char& c : out)
        if (c >= 'a' && c <= 'z') c = c - 'a' + 'A';
    return out;
}

//! 8-bit bytes to 5-bit groups, zero padded.
std::vector<uint8_t> ToGroups(const std::vector<unsigned char>& bytes)
{
    std::vector<uint8_t> out;
    uint32_t acc = 0;
    unsigned int bits = 0;
    for (unsigned char b : bytes) {
        acc = ((acc << 8) | b) & 0xfff;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back((acc >> bits) & 31);
        }
    }
    if (bits) out.push_back((acc << (5 - bits)) & 31);
    return out;
}

//! 5-bit groups from index `from` to bytes; false when a spare group or
//! non-zero padding bits are left over.
bool FromGroups(const std::vector<uint8_t>& groups, size_t from, std::vector<unsigned char>& out)
{
    out.clear();
    uint32_t acc = 0;
    unsigned int bits = 0;
    for (size_t i = from; i < groups.size(); ++i) {
        acc = ((acc << 5) | groups[i]) & 0xfff;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            out.push_back((acc >> bits) & 0xff);
        }
    }
    return bits < 5 && ((acc << (8 - bits)) & 0xff) == 0;
}

//! The first check `str` fails as an address of `version` on a network with
//! `prefix`, by the names the vector file uses; empty when it fails none.
std::string FirstFailedCheck(const std::string& str, const std::string& prefix, int version)
{
    static const std::string charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    if (str.empty()) return "empty";
    bool lower = false, upper = false;
    for (unsigned char c : str) {
        if (c < 33 || c > 126) return "whitespace";
        if (c >= 'a' && c <= 'z') lower = true;
        if (c >= 'A' && c <= 'Z') upper = true;
    }
    if (lower && upper) return "mixed_case";
    if (str.size() > 90) return "length_over_90";
    const size_t pos = str.rfind('1');
    if (pos == std::string::npos) return "separator_missing";
    if (pos == 0) return "prefix_empty";
    if (pos + 7 > str.size()) return "checksum_short";
    for (size_t i = pos + 1; i < str.size(); ++i) {
        char c = str[i];
        if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
        if (charset.find(c) == std::string::npos) return "character";
    }
    const bech32::DecodeResult dec = bech32::Decode(str);
    if (dec.encoding == bech32::Encoding::BECH32) return "checksum_bech32";
    if (dec.encoding != bech32::Encoding::BECH32M) return "checksum";
    if (dec.hrp != prefix) return "prefix";
    if (dec.data.empty() || dec.data[0] != version) return "version";
    std::vector<unsigned char> program;
    if (!FromGroups(dec.data, 1, program)) return "padding";
    if (program.size() != 32) return "program_length";
    return std::string();
}

//! The output script of a witness program: the version opcode, the push, the program.
CScript WitnessScript(int version, const std::vector<unsigned char>& program)
{
    return CScript() << CScript::EncodeOP_N(version) << program;
}

//! The bytes WitnessScript must give for a 32-byte program.
std::vector<unsigned char> WitnessScriptBytes(int version, const std::vector<unsigned char>& program)
{
    std::vector<unsigned char> bytes;
    bytes.push_back(0x50 + version);
    bytes.push_back(program.size());
    bytes.insert(bytes.end(), program.begin(), program.end());
    return bytes;
}

std::string ScriptHex(const CScript& script)
{
    return HexStr(script.begin(), script.end());
}

struct RpcResult {
    bool ok;
    UniValue value;      //!< the result when ok
    int code;            //!< the error code when not ok
    std::string message; //!< the error message when not ok

    RpcResult() : ok(false), code(0) {}
};

//! Call an RPC through the dispatch table. An error the handler raises as a
//! JSON-RPC error keeps its code; any other exception (the usage text among
//! them) is reported as RPC_MISC_ERROR, as the server reports it.
RpcResult CallRpc(const std::string& method, const UniValue& params)
{
    JSONRPCRequest request;
    request.strMethod = method;
    request.params = params;
    request.fHelp = false;
    const CRPCCommand* command = tableRPC[method];
    BOOST_REQUIRE_MESSAGE(command != nullptr, method + " is not registered");

    RpcResult result;
    try {
        result.value = (*command->actor)(request);
        result.ok = true;
    } catch (const UniValue& error) {
        result.code = find_value(error, "code").get_int();
        result.message = find_value(error, "message").get_str();
    } catch (const std::exception& e) {
        result.code = RPC_MISC_ERROR;
        result.message = e.what();
    }
    return result;
}

//! A JSON array of parameters from its text.
UniValue Json(const std::string& text)
{
    UniValue value;
    BOOST_REQUIRE_MESSAGE(value.read(text) && value.isArray(), "not a JSON array: " + text);
    return value;
}

UniValue Params1(const std::string& only)
{
    UniValue params(UniValue::VARR);
    params.push_back(only);
    return params;
}

//! Parameters of createrawtransaction paying 1 coin to `address` from no input.
UniValue PayTo(const std::string& address)
{
    UniValue outputs(UniValue::VOBJ);
    outputs.pushKV(address, 1);
    UniValue params(UniValue::VARR);
    params.push_back(UniValue(UniValue::VARR));
    params.push_back(outputs);
    return params;
}

//! The "addresses" a decoded script shows, or an empty list when it shows none.
std::vector<std::string> ShownAddresses(const UniValue& scriptPubKey)
{
    std::vector<std::string> out;
    const UniValue& addresses = find_value(scriptPubKey, "addresses");
    if (addresses.isArray())
        for (size_t i = 0; i < addresses.size(); ++i)
            out.push_back(addresses[i].get_str());
    return out;
}

const char* const TXID_A = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const char* const TXID_B = "f0e0d0c0b0a090807060504030201000ffeeddccbbaa99887766554433221100";

//! The version 1 address of the program 00 01 .. 1f on a network with `prefix`.
std::string SequentialV1Address(const VectorFile& file, const std::string& prefix)
{
    std::vector<unsigned char> program;
    for (int i = 0; i < 32; ++i) program.push_back(i);
    for (const ValidVector& v : file.valid)
        if (v.prefix == prefix && v.version == 1 && v.program == program) return v.address;
    BOOST_FAIL("the vector file has no version 1 vector for the program 00..1f on " + prefix);
    return std::string();
}

} // namespace

BOOST_AUTO_TEST_SUITE(witness_v6_address_tests)

// ---------------------------------------------------------------------------
// The vector file
// ---------------------------------------------------------------------------

// The file's network map is the prefix chainparams gives each network, and it
// names every network the node can select.
BOOST_FIXTURE_TEST_CASE(file_network_map_is_chainparams, BasicTestingSetup)
{
    const VectorFile file = LoadVectors();
    const std::vector<std::string> networks = NodeNetworks();
    BOOST_CHECK_EQUAL(file.networks.size(), networks.size());
    for (const std::string& network : networks) {
        NetworkScope scope(network);
        BOOST_REQUIRE_MESSAGE(file.networks.count(network), "the file does not name network " + network);
        BOOST_CHECK_EQUAL(file.networks.at(network), Params().Bech32HRP());
    }

    // Every vector belongs to a prefix some network uses, and every prefix has
    // valid vectors of both versions.
    std::set<std::string> prefixes;
    for (const auto& entry : file.networks) prefixes.insert(entry.second);
    std::map<std::pair<std::string, int>, int> count;
    for (const ValidVector& v : file.valid) {
        BOOST_CHECK_MESSAGE(prefixes.count(v.prefix), "valid vector with an unused prefix: " + v.address);
        BOOST_CHECK_MESSAGE(v.version == 1 || v.version == 6, "valid vector of another version: " + v.address);
        BOOST_CHECK_EQUAL(v.program.size(), 32u);
        ++count[std::make_pair(v.prefix, v.version)];
    }
    for (const InvalidVector& v : file.invalid) {
        BOOST_CHECK_MESSAGE(prefixes.count(v.prefix), "invalid vector with an unused prefix: " + v.address);
        BOOST_CHECK_MESSAGE(v.version == 1 || v.version == 6, "invalid vector of another version: " + v.address);
    }
    for (const std::string& prefix : prefixes) {
        BOOST_CHECK_MESSAGE(count[std::make_pair(prefix, 1)] > 0, "no valid version 1 vector for " + prefix);
        BOOST_CHECK_MESSAGE(count[std::make_pair(prefix, 6)] > 0, "no valid version 6 vector for " + prefix);
    }
}

// Every valid string is the bech32m encoding of its version and program, by
// bech32::Encode and the bit conversion in this file, and fails no check.
BOOST_FIXTURE_TEST_CASE(file_valid_strings_are_rebuilt, BasicTestingSetup)
{
    const VectorFile file = LoadVectors();
    for (const ValidVector& v : file.valid) {
        std::vector<uint8_t> data;
        data.push_back(v.version);
        const std::vector<uint8_t> groups = ToGroups(v.program);
        data.insert(data.end(), groups.begin(), groups.end());
        BOOST_CHECK_EQUAL(bech32::Encode(bech32::Encoding::BECH32M, v.prefix, data), v.address);
        BOOST_CHECK_EQUAL(FirstFailedCheck(v.address, v.prefix, v.version), "");
        BOOST_CHECK_EQUAL(FirstFailedCheck(Upper(v.address), v.prefix, v.version), "");
    }
}

// Every invalid string fails the check its reason names and none before it,
// and every reason is present for each prefix and version.
BOOST_FIXTURE_TEST_CASE(file_invalid_strings_fail_the_named_check, BasicTestingSetup)
{
    const VectorFile file = LoadVectors();
    const std::vector<std::string> reasons = {
        "empty", "whitespace", "mixed_case", "length_over_90", "separator_missing", "prefix_empty",
        "checksum_short", "character", "checksum_bech32", "checksum", "prefix", "version", "padding",
        "program_length"};

    std::set<std::string> prefixes;
    for (const auto& entry : file.networks) prefixes.insert(entry.second);

    std::map<std::string, int> seen;
    for (const InvalidVector& v : file.invalid) {
        BOOST_CHECK_MESSAGE(FirstFailedCheck(v.address, v.prefix, v.version) == v.reason,
            "'" + v.address + "' is listed as " + v.reason + " and fails " +
            FirstFailedCheck(v.address, v.prefix, v.version));
        ++seen[v.prefix + "/" + std::to_string(v.version) + "/" + v.reason];
    }
    for (const std::string& prefix : prefixes)
        for (int version : {1, 6})
            for (const std::string& reason : reasons)
                BOOST_CHECK_MESSAGE(seen[prefix + "/" + std::to_string(version) + "/" + reason] > 0,
                    "no invalid vector for " + prefix + " version " + std::to_string(version) + " reason " + reason);

    // Every program length from 0 to 40 bytes other than 32 is among them.
    for (const std::string& prefix : prefixes)
        for (int version : {1, 6}) {
            std::set<size_t> lengths;
            for (const InvalidVector& v : file.invalid) {
                if (v.prefix != prefix || v.version != version || v.reason != "program_length") continue;
                const bech32::DecodeResult dec = bech32::Decode(v.address);
                std::vector<unsigned char> program;
                BOOST_REQUIRE(FromGroups(dec.data, 1, program));
                lengths.insert(program.size());
            }
            for (size_t length = 0; length <= 40; ++length)
                BOOST_CHECK_MESSAGE((length == 32) != (lengths.count(length) > 0),
                    "program length " + std::to_string(length) + " for " + prefix + " version " + std::to_string(version));
        }
}

// ---------------------------------------------------------------------------
// Version 1: EncodeDestination and DecodeDestination
// ---------------------------------------------------------------------------

BOOST_FIXTURE_TEST_CASE(v1_vectors_encode_and_decode, BasicTestingSetup)
{
    const VectorFile file = LoadVectors();
    for (const std::string& network : NodeNetworks()) {
        NetworkScope scope(network);
        const std::string hrp = Params().Bech32HRP();
        int run = 0;
        for (const ValidVector& v : file.valid) {
            if (v.version != 1) continue;
            if (v.prefix != hrp) {
                // Another network's address.
                BOOST_CHECK_MESSAGE(!IsValidDestination(DecodeDestination(v.address, hrp)), network + " accepts " + v.address);
                BOOST_CHECK(!IsValidDestinationString(v.address, hrp));
                continue;
            }
            ++run;
            WitnessV1ScriptHash hash;
            std::copy(v.program.begin(), v.program.end(), hash.begin());
            BOOST_CHECK_EQUAL(EncodeDestination(CTxDestination(hash), hrp), v.address);

            for (const std::string& form : {v.address, Upper(v.address)}) {
                const CTxDestination dest = DecodeDestination(form, hrp);
                BOOST_REQUIRE_MESSAGE(IsValidDestination(dest), network + " refuses " + form);
                BOOST_CHECK(IsValidDestinationString(form, hrp));
                const WitnessV1ScriptHash* decoded = boost::get<WitnessV1ScriptHash>(&dest);
                BOOST_REQUIRE(decoded != nullptr);
                BOOST_CHECK(std::vector<unsigned char>(decoded->begin(), decoded->end()) == v.program);

                const CScript script = GetScriptForDestination(dest);
                BOOST_CHECK(script == WitnessScript(1, v.program));
                BOOST_CHECK(std::vector<unsigned char>(script.begin(), script.end()) == WitnessScriptBytes(1, v.program));
            }
        }
        BOOST_CHECK_MESSAGE(run > 0, "no version 1 vector ran on " + network);
    }
}

BOOST_FIXTURE_TEST_CASE(v1_decoder_refuses_invalid_vectors, BasicTestingSetup)
{
    const VectorFile file = LoadVectors();
    for (const std::string& network : NodeNetworks()) {
        NetworkScope scope(network);
        const std::string hrp = Params().Bech32HRP();
        int run = 0;
        for (const InvalidVector& v : file.invalid) {
            if (v.version != 1 || v.prefix != hrp) continue;
            ++run;
            BOOST_CHECK_MESSAGE(!IsValidDestination(DecodeDestination(v.address, hrp)),
                network + " accepts '" + v.address + "' (" + v.reason + ")");
            BOOST_CHECK(!IsValidDestinationString(v.address, hrp));
            BOOST_CHECK(!IsValidDestination(DecodeDilithiumAddress(v.address, hrp)));
        }
        BOOST_CHECK_MESSAGE(run > 0, "no invalid version 1 vector ran on " + network);
    }
}

// DecodeDestination accepts version 1 only: every version 6 address, valid
// for the network or not, is refused in either case.
BOOST_FIXTURE_TEST_CASE(v1_decoder_refuses_v6_addresses, BasicTestingSetup)
{
    const VectorFile file = LoadVectors();
    for (const std::string& network : NodeNetworks()) {
        NetworkScope scope(network);
        const std::string hrp = Params().Bech32HRP();
        int run = 0;
        for (const ValidVector& v : file.valid) {
            if (v.version != 6) continue;
            ++run;
            for (const std::string& form : {v.address, Upper(v.address)}) {
                BOOST_CHECK_MESSAGE(!IsValidDestination(DecodeDestination(form, hrp)), network + " accepts " + form);
                BOOST_CHECK(!IsValidDestinationString(form, hrp));
                BOOST_CHECK(!IsValidDestination(DecodeDilithiumAddress(form, hrp)));
            }
        }
        BOOST_CHECK_MESSAGE(run > 0, "no version 6 vector ran on " + network);
    }
}

// ---------------------------------------------------------------------------
// Version 6: EncodeWitnessV6Address and DecodeWitnessV6Address
// ---------------------------------------------------------------------------

BOOST_FIXTURE_TEST_CASE(v6_vectors_encode_and_decode, BasicTestingSetup)
{
    const VectorFile file = LoadVectors();
    for (const std::string& network : NodeNetworks()) {
        NetworkScope scope(network);
        const std::string hrp = Params().Bech32HRP();
        int run = 0;
        for (const ValidVector& v : file.valid) {
            if (v.version != 6 || v.prefix != hrp) continue;
            ++run;
            BOOST_CHECK_EQUAL(EncodeWitnessV6Address(v.program, hrp), v.address);
            for (const std::string& form : {v.address, Upper(v.address)}) {
                std::vector<unsigned char> program;
                BOOST_CHECK_MESSAGE(DecodeWitnessV6Address(form, hrp, program), network + " refuses " + form);
                BOOST_CHECK(program == v.program);

                // The script a funder builds from the decoded program.
                const CScript script = WitnessScript(6, program);
                BOOST_CHECK(std::vector<unsigned char>(script.begin(), script.end()) == WitnessScriptBytes(6, v.program));
            }
        }
        BOOST_CHECK_MESSAGE(run > 0, "no version 6 vector ran on " + network);
    }
}

BOOST_FIXTURE_TEST_CASE(v6_decoder_refuses_invalid_vectors, BasicTestingSetup)
{
    const VectorFile file = LoadVectors();
    for (const std::string& network : NodeNetworks()) {
        NetworkScope scope(network);
        const std::string hrp = Params().Bech32HRP();
        int run = 0;
        for (const InvalidVector& v : file.invalid) {
            if (v.version != 6 || v.prefix != hrp) continue;
            ++run;
            std::vector<unsigned char> program(1, 0x42);
            BOOST_CHECK_MESSAGE(!DecodeWitnessV6Address(v.address, hrp, program),
                network + " accepts '" + v.address + "' (" + v.reason + ")");
            // A refusal leaves the caller's program as it was.
            BOOST_CHECK(program == std::vector<unsigned char>(1, 0x42));
        }
        BOOST_CHECK_MESSAGE(run > 0, "no invalid version 6 vector ran on " + network);
    }
}

// The version 6 decoder refuses every version 1 address, and every version 6
// address of a network with another prefix.
BOOST_FIXTURE_TEST_CASE(v6_decoder_refuses_v1_and_other_networks, BasicTestingSetup)
{
    const VectorFile file = LoadVectors();
    for (const std::string& network : NodeNetworks()) {
        NetworkScope scope(network);
        const std::string hrp = Params().Bech32HRP();
        int run = 0;
        for (const ValidVector& v : file.valid) {
            if (v.version == 6 && v.prefix == hrp) continue;
            ++run;
            for (const std::string& form : {v.address, Upper(v.address)}) {
                std::vector<unsigned char> program;
                BOOST_CHECK_MESSAGE(!DecodeWitnessV6Address(form, hrp, program), network + " accepts " + form);
            }
        }
        BOOST_CHECK_MESSAGE(run > 0, "no vector ran on " + network);
    }
}

// The encoder gives an address for a 32-byte program and for no other length,
// and the decoder gives back what the encoder was given.
BOOST_FIXTURE_TEST_CASE(v6_encoder_takes_32_bytes_only, BasicTestingSetup)
{
    for (const std::string& network : NodeNetworks()) {
        NetworkScope scope(network);
        const std::string hrp = Params().Bech32HRP();
        for (size_t length = 0; length <= 64; ++length) {
            std::vector<unsigned char> program;
            for (size_t i = 0; i < length; ++i) program.push_back(0xa5 ^ i);
            const std::string address = EncodeWitnessV6Address(program, hrp);
            if (length != 32) {
                BOOST_CHECK_MESSAGE(address.empty(), "an address for a program of " + std::to_string(length) + " bytes");
                continue;
            }
            BOOST_CHECK_EQUAL(address.size(), hrp.size() + 60);
            BOOST_CHECK_EQUAL(address.substr(0, hrp.size() + 2), hrp + "1x");
            BOOST_CHECK_EQUAL(FirstFailedCheck(address, hrp, 6), "");
            std::vector<unsigned char> decoded;
            BOOST_CHECK(DecodeWitnessV6Address(address, hrp, decoded));
            BOOST_CHECK(decoded == program);
        }
    }
}

// ---------------------------------------------------------------------------
// createrawtransaction
// ---------------------------------------------------------------------------

// The transactions createrawtransaction builds without the version argument,
// byte for byte.
BOOST_FIXTURE_TEST_CASE(createrawtransaction_bytes_without_version, TestingSetup)
{
    const VectorFile file = LoadVectors();
    const std::string v1 = SequentialV1Address(file, Params().Bech32HRP());
    const std::string legacy = CBitcoinAddress(CKeyID(uint160(std::vector<unsigned char>(20, 0x11)))).ToString();
    const std::string in_a = std::string("{\"txid\":\"") + TXID_A + "\",\"vout\":0}";
    const std::string in_b = std::string("{\"txid\":\"") + TXID_B + "\",\"vout\":3,\"sequence\":5}";

    // No input, no output.
    RpcResult empty = CallRpc("createrawtransaction", Json("[[], {}]"));
    BOOST_REQUIRE_MESSAGE(empty.ok, empty.message);
    BOOST_CHECK_EQUAL(empty.value.get_str(), "01000000000000000000");

    // One input, one version 1 output.
    const std::string one = "[[" + in_a + "], {\"" + v1 + "\":1}";
    RpcResult simple = CallRpc("createrawtransaction", Json(one + "]"));
    BOOST_REQUIRE_MESSAGE(simple.ok, simple.message);
    BOOST_CHECK_EQUAL(simple.value.get_str(),
        "0100000001201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000000000ffffffff"
        "0100e1f50500000000225120000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000");

    // The same with the locktime given as null and as 0.
    RpcResult with_null = CallRpc("createrawtransaction", Json(one + ", null]"));
    BOOST_REQUIRE_MESSAGE(with_null.ok, with_null.message);
    BOOST_CHECK_EQUAL(with_null.value.get_str(), simple.value.get_str());
    RpcResult with_zero = CallRpc("createrawtransaction", Json(one + ", 0]"));
    BOOST_REQUIRE_MESSAGE(with_zero.ok, with_zero.message);
    BOOST_CHECK_EQUAL(with_zero.value.get_str(), simple.value.get_str());

    // Two inputs, one with a sequence; a version 1 output, a data output and a
    // Base58 key-hash output; a locktime.
    RpcResult full = CallRpc("createrawtransaction", Json("[[" + in_a + "," + in_b + "], {\"" + v1 +
        "\":12.5,\"data\":\"00010203\",\"" + legacy + "\":\"0.00000001\"}, 500000]"));
    BOOST_REQUIRE_MESSAGE(full.ok, full.message);
    BOOST_CHECK_EQUAL(full.value.get_str(),
        "0100000002201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000000000feffffff"
        "00112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0030000000005000000"
        "03807c814a00000000225120000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "0000000000000000066a0400010203"
        "01000000000000001976a914111111111111111111111111111111111111111188ac"
        "20a10700");
}

// The fourth argument sets the transaction version: 1 to
// CTransaction::MAX_STANDARD_VERSION, 1 when it is omitted or null.
BOOST_FIXTURE_TEST_CASE(createrawtransaction_version_argument, TestingSetup)
{
    const VectorFile file = LoadVectors();
    const std::string v1 = SequentialV1Address(file, Params().Bech32HRP());
    const std::string head = std::string("[[{\"txid\":\"") + TXID_A + "\",\"vout\":0,\"sequence\":144}], {\"" + v1 + "\":1}";

    RpcResult base = CallRpc("createrawtransaction", Json(head + "]"));
    BOOST_REQUIRE_MESSAGE(base.ok, base.message);
    const std::string base_hex = base.value.get_str();
    BOOST_CHECK_EQUAL(base_hex.substr(0, 8), "01000000");

    for (const std::string& tail : {", 0, null]", ", null, null]", ", 0, 1]", ", null, 1]"}) {
        RpcResult same = CallRpc("createrawtransaction", Json(head + tail));
        BOOST_REQUIRE_MESSAGE(same.ok, tail + ": " + same.message);
        BOOST_CHECK_EQUAL(same.value.get_str(), base_hex);
    }

    // Every version relay accepts, and only the version field differs.
    BOOST_REQUIRE(CTransaction::MAX_STANDARD_VERSION >= 2);
    for (int32_t version = 1; version <= CTransaction::MAX_STANDARD_VERSION; ++version) {
        RpcResult built = CallRpc("createrawtransaction", Json(head + ", 0, " + std::to_string(version) + "]"));
        BOOST_REQUIRE_MESSAGE(built.ok, "version " + std::to_string(version) + ": " + built.message);
        CMutableTransaction tx;
        BOOST_REQUIRE(DecodeHexTx(tx, built.value.get_str(), true));
        BOOST_CHECK_EQUAL(tx.nVersion, version);
        BOOST_CHECK_EQUAL(built.value.get_str().substr(8), base_hex.substr(8));
    }
    RpcResult two = CallRpc("createrawtransaction", Json(head + ", null, 2]"));
    BOOST_REQUIRE_MESSAGE(two.ok, two.message);
    BOOST_CHECK_EQUAL(two.value.get_str(), "02000000" + base_hex.substr(8));

    // With a locktime.
    RpcResult locked = CallRpc("createrawtransaction", Json(head + ", 500000, 2]"));
    BOOST_REQUIRE_MESSAGE(locked.ok, locked.message);
    CMutableTransaction tx;
    BOOST_REQUIRE(DecodeHexTx(tx, locked.value.get_str(), true));
    BOOST_CHECK_EQUAL(tx.nVersion, 2);
    BOOST_CHECK_EQUAL(tx.nLockTime, 500000u);
    BOOST_CHECK_EQUAL(tx.vin[0].nSequence, 144u);
}

BOOST_FIXTURE_TEST_CASE(createrawtransaction_refuses_other_versions, TestingSetup)
{
    const VectorFile file = LoadVectors();
    const std::string v1 = SequentialV1Address(file, Params().Bech32HRP());
    const std::string head = std::string("[[{\"txid\":\"") + TXID_A + "\",\"vout\":0}], {\"" + v1 + "\":1}, 0, ";

    // Integers outside the range, and numbers that are not integers. The two
    // above 2^32 would be 1 and 2 if the value were cut to 32 bits.
    const std::vector<std::string> out_of_range = {
        "0", "-1", std::to_string((int64_t)CTransaction::MAX_STANDARD_VERSION + 1), "2147483647", "2147483648",
        "-2147483648", "4294967297", "4294967298", "9223372036854775807", "99999999999999999999",
        "1.5", "1.0", "2.0", "1e0", "0.2e1"};
    for (const std::string& value : out_of_range) {
        RpcResult refused = CallRpc("createrawtransaction", Json(head + value + "]"));
        BOOST_CHECK_MESSAGE(!refused.ok, "version " + value + " was accepted");
        BOOST_CHECK_MESSAGE(refused.code == RPC_INVALID_PARAMETER, "version " + value + ": code " + std::to_string(refused.code));
        BOOST_CHECK_EQUAL(refused.message, "Invalid parameter, version out of range");
    }

    // Values that are not numbers.
    for (const std::string& value : {"\"2\"", "\"\"", "true", "false", "[2]", "{\"version\":2}"}) {
        RpcResult refused = CallRpc("createrawtransaction", Json(head + value + "]"));
        BOOST_CHECK_MESSAGE(!refused.ok, "version " + value + " was accepted");
        BOOST_CHECK_MESSAGE(refused.code == RPC_TYPE_ERROR, "version " + value + ": code " + std::to_string(refused.code));
    }

    // A fifth argument.
    RpcResult five = CallRpc("createrawtransaction", Json(head + "1, 1]"));
    BOOST_CHECK(!five.ok);
    BOOST_CHECK_EQUAL(five.code, (int)RPC_MISC_ERROR);
}

// The command line converts the version from text to a number, and the
// argument has a name.
BOOST_FIXTURE_TEST_CASE(createrawtransaction_version_conversion_and_name, TestingSetup)
{
    const UniValue params = RPCConvertValues("createrawtransaction", {"[]", "{}", "0", "2"});
    BOOST_REQUIRE_EQUAL(params.size(), 4u);
    BOOST_CHECK(params[2].isNum());
    BOOST_CHECK_MESSAGE(params[3].isNum(), "the version reaches the server as text");

    RpcResult built = CallRpc("createrawtransaction", params);
    BOOST_REQUIRE_MESSAGE(built.ok, built.message);
    BOOST_CHECK_EQUAL(built.value.get_str(), "02000000000000000000");

    const CRPCCommand* command = tableRPC["createrawtransaction"];
    BOOST_REQUIRE(command != nullptr);
    const std::vector<std::string> names = {"inputs", "outputs", "locktime", "version"};
    BOOST_CHECK(command->argNames == names);
}

// createrawtransaction refuses a version 6 address on every network, in
// either case, with the error it gives any string that is no address.
BOOST_FIXTURE_TEST_CASE(createrawtransaction_refuses_v6_address, TestingSetup)
{
    const VectorFile file = LoadVectors();
    for (const std::string& network : NodeNetworks()) {
        NetworkScope scope(network);
        const std::string hrp = Params().Bech32HRP();
        int run = 0;
        for (const ValidVector& v : file.valid) {
            if (v.version != 6) continue;
            ++run;
            for (const std::string& form : {v.address, Upper(v.address)}) {
                RpcResult refused = CallRpc("createrawtransaction", PayTo(form));
                BOOST_CHECK_MESSAGE(!refused.ok, network + " builds an output for " + form);
                BOOST_CHECK_EQUAL(refused.code, (int)RPC_INVALID_ADDRESS_OR_KEY);
                BOOST_CHECK_EQUAL(refused.message, "Invalid Soqucoin address: " + form);
            }
        }
        BOOST_CHECK_MESSAGE(run > 0, "no version 6 vector ran on " + network);

        // Control: the version 1 address of the network's prefix builds.
        RpcResult built = CallRpc("createrawtransaction", PayTo(SequentialV1Address(file, hrp)));
        BOOST_CHECK_MESSAGE(built.ok, network + ": " + built.message);
    }
}

// validateaddress: a version 6 address is not valid, a version 1 address is.
BOOST_FIXTURE_TEST_CASE(validateaddress_refuses_v6_address, TestingSetup)
{
    const VectorFile file = LoadVectors();
    for (const std::string& network : NodeNetworks()) {
        NetworkScope scope(network);
        const std::string hrp = Params().Bech32HRP();
        for (const ValidVector& v : file.valid) {
            RpcResult result = CallRpc("validateaddress", Params1(v.address));
            BOOST_REQUIRE_MESSAGE(result.ok, result.message);
            const bool expected = v.version == 1 && v.prefix == hrp;
            BOOST_CHECK_MESSAGE(find_value(result.value, "isvalid").get_bool() == expected,
                network + " validateaddress " + v.address);
        }
    }
}

// ---------------------------------------------------------------------------
// The address a decoded script shows
// ---------------------------------------------------------------------------

BOOST_FIXTURE_TEST_CASE(decodescript_shows_the_v6_address, TestingSetup)
{
    const VectorFile file = LoadVectors();
    for (const std::string& network : NodeNetworks()) {
        NetworkScope scope(network);
        const std::string hrp = Params().Bech32HRP();
        int run = 0;
        for (const ValidVector& v : file.valid) {
            if (v.prefix != hrp) continue;
            ++run;
            const CScript script = WitnessScript(v.version, v.program);
            BOOST_REQUIRE(std::vector<unsigned char>(script.begin(), script.end()) == WitnessScriptBytes(v.version, v.program));
            RpcResult decoded = CallRpc("decodescript", Params1(ScriptHex(script)));
            BOOST_REQUIRE_MESSAGE(decoded.ok, decoded.message);
            const txnouttype type = v.version == 6 ? TX_WITNESS_V6_COVENANT : TX_WITNESS_V1_SCRIPTHASH;
            BOOST_CHECK_EQUAL(find_value(decoded.value, "type").get_str(), GetTxnOutputType(type));
            const std::vector<std::string> shown = ShownAddresses(decoded.value);
            BOOST_CHECK_MESSAGE(shown.size() == 1 && shown[0] == v.address,
                network + " decodescript of version " + std::to_string(v.version) + " shows " +
                (shown.empty() ? std::string("no address") : shown[0]) + ", expected " + v.address);
        }
        BOOST_CHECK_MESSAGE(run > 0, "no vector ran on " + network);
    }
}

// No other witness version and no other program length gains an address.
BOOST_FIXTURE_TEST_CASE(decodescript_shows_no_address_for_other_forms, TestingSetup)
{
    const std::vector<unsigned char> program(32, 0x33);
    for (int version = 0; version <= 16; ++version) {
        if (version == 1 || version == 6) continue;
        RpcResult decoded = CallRpc("decodescript", Params1(ScriptHex(WitnessScript(version, program))));
        BOOST_REQUIRE_MESSAGE(decoded.ok, decoded.message);
        BOOST_CHECK_MESSAGE(ShownAddresses(decoded.value).empty(), "an address for witness version " + std::to_string(version));
    }
    for (size_t length : {2u, 20u, 31u, 33u, 40u}) {
        RpcResult decoded = CallRpc("decodescript",
            Params1(ScriptHex(WitnessScript(6, std::vector<unsigned char>(length, 0x33)))));
        BOOST_REQUIRE_MESSAGE(decoded.ok, decoded.message);
        BOOST_CHECK_MESSAGE(ShownAddresses(decoded.value).empty(),
            "an address for a version 6 program of " + std::to_string(length) + " bytes");
    }
}

// Version 6 outputs built here from the vectors' programs are funded in a
// mined regtest block. decoderawtransaction on the funding transaction and
// gettxout on the mined outputs show each vector's address beside the script
// bytes of its program.
BOOST_FIXTURE_TEST_CASE(mined_v6_outputs_show_their_addresses, DilithiumChainSetup)
{
    const VectorFile file = LoadVectors();
    const std::string hrp = Params().Bech32HRP();
    std::vector<ValidVector> vectors;
    for (const ValidVector& v : file.valid)
        if (v.version == 6 && v.prefix == hrp) vectors.push_back(v);
    BOOST_REQUIRE(!vectors.empty());

    const CAmount fee = 1000000;
    const CAmount in_value = coinbaseTxns[0].vout[0].nValue;
    const CAmount each = (in_value - fee) / (CAmount)vectors.size();
    BOOST_REQUIRE(each > 0);

    CMutableTransaction funding;
    funding.nVersion = 2;
    funding.vin.push_back(CTxIn(COutPoint(coinbaseTxns[0].GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
    for (const ValidVector& v : vectors)
        funding.vout.push_back(CTxOut(each, WitnessScript(6, v.program)));
    SignInput(funding, 0, coinbaseSpk, in_value);

    const int height = chainActive.Height();
    CreateAndProcessBlock({funding}, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Height() == height + 1, "the block funding the version 6 outputs did not connect");

    RpcResult decoded = CallRpc("decoderawtransaction", Params1(EncodeHexTx(funding)));
    BOOST_REQUIRE_MESSAGE(decoded.ok, decoded.message);
    const UniValue& vout = find_value(decoded.value, "vout");
    BOOST_REQUIRE_EQUAL(vout.size(), vectors.size());

    for (size_t i = 0; i < vectors.size(); ++i) {
        const std::string script_hex = HexStr(WitnessScriptBytes(6, vectors[i].program));

        const UniValue& spk = find_value(vout[i], "scriptPubKey");
        BOOST_CHECK_EQUAL(find_value(spk, "hex").get_str(), script_hex);
        BOOST_CHECK_EQUAL(find_value(spk, "type").get_str(), GetTxnOutputType(TX_WITNESS_V6_COVENANT));
        std::vector<std::string> shown = ShownAddresses(spk);
        BOOST_CHECK_MESSAGE(shown.size() == 1 && shown[0] == vectors[i].address,
            "decoderawtransaction output " + std::to_string(i) + " shows " +
            (shown.empty() ? std::string("no address") : shown[0]) + ", expected " + vectors[i].address);

        UniValue params(UniValue::VARR);
        params.push_back(funding.GetHash().GetHex());
        params.push_back((int)i);
        RpcResult coin = CallRpc("gettxout", params);
        BOOST_REQUIRE_MESSAGE(coin.ok, coin.message);
        BOOST_REQUIRE_MESSAGE(coin.value.isObject(), "output " + std::to_string(i) + " is not in the UTXO set");
        BOOST_CHECK_EQUAL(find_value(coin.value, "confirmations").get_int(), 1);
        const UniValue& coin_spk = find_value(coin.value, "scriptPubKey");
        BOOST_CHECK_EQUAL(find_value(coin_spk, "hex").get_str(), script_hex);
        shown = ShownAddresses(coin_spk);
        BOOST_CHECK_MESSAGE(shown.size() == 1 && shown[0] == vectors[i].address,
            "gettxout output " + std::to_string(i) + " shows " +
            (shown.empty() ? std::string("no address") : shown[0]) + ", expected " + vectors[i].address);
    }
}

BOOST_AUTO_TEST_SUITE_END()
