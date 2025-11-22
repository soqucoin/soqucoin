// Copyright (c) 2021-2023 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utiladdress.h"
#include "bech32.h"
#include "chainparams.h"
#include "hash.h"
#include "pubkey.h"
#include "script/standard.h"

#include <algorithm>

namespace
{

std::vector<uint8_t> ConvertBits(const std::vector<uint8_t>& data, int frombits, int tobits, bool pad)
{
    int acc = 0;
    int bits = 0;
    std::vector<uint8_t> ret;
    int maxv = (1 << tobits) - 1;

    for (const auto& value : data) {
        acc = (acc << frombits) | value;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            ret.push_back((acc >> bits) & maxv);
        }
    }

    if (pad) {
        if (bits) ret.push_back((acc << (tobits - bits)) & maxv);
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return {};
    }

    return ret;
}

} // namespace

std::string EncodeDestination(const CTxDestination& dest, const std::string& hrp)
{
    if (dest.which() == 3) { // WitnessV1ScriptHash
        const WitnessV1ScriptHash* witness_v1 = boost::get<WitnessV1ScriptHash>(&dest);
        if (witness_v1) {
            std::vector<uint8_t> data(witness_v1->begin(), witness_v1->end());
            std::vector<uint8_t> conv = ConvertBits(data, 8, 5, true);
            std::vector<uint8_t> enc;
            enc.push_back(1); // witness version 1
            enc.insert(enc.end(), conv.begin(), conv.end());
            return bech32::Encode(bech32::Encoding::BECH32M, hrp, enc);
        }
    }

    // For other destination types, return empty string (legacy not supported)
    return "";
}

CTxDestination DecodeDestination(const std::string& str, const std::string& hrp)
{
    bech32::DecodeResult dec = bech32::Decode(str);

    if (dec.encoding == bech32::Encoding::BECH32M && dec.hrp == hrp && !dec.data.empty()) {
        // Witness v1 (Dilithium)
        if (dec.data[0] == 1) {
            std::vector<uint8_t> conv = ConvertBits(
                std::vector<uint8_t>(dec.data.begin() + 1, dec.data.end()),
                5, 8, false);

            if (conv.size() == 32) {
                WitnessV1ScriptHash hash;
                std::copy(conv.begin(), conv.end(), hash.begin());
                return hash;
            }
        }
    }

    return CNoDestination();
}

bool IsValidDestination(const CTxDestination& dest)
{
    return dest.which() != 0; // Not CNoDestination
}

bool IsValidDestinationString(const std::string& str, const std::string& hrp)
{
    CTxDestination dest = DecodeDestination(str, hrp);
    return dest.which() != 0; // Not CNoDestination
}

std::string EncodeDilithiumAddress(const CPubKey& pubkey, const std::string& hrp)
{
    // Hash the Dilithium public key to create witness v1 script hash
    std::vector<unsigned char> pubkey_data(pubkey.begin(), pubkey.end());

    // Use single SHA256 to create the 32-byte witness program (same as getnewaddress)
    uint256 hash;
    CSHA256().Write(pubkey_data.data(), pubkey_data.size()).Finalize(hash.begin());

    WitnessV1ScriptHash witness_hash;
    std::copy(hash.begin(), hash.end(), witness_hash.begin());

    return EncodeDestination(witness_hash, hrp);
}

CTxDestination DecodeDilithiumAddress(const std::string& addr, const std::string& hrp)
{
    return DecodeDestination(addr, hrp);
}
