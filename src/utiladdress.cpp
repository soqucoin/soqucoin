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
    // The accumulator is unsigned and masked to the bits not yet written out,
    // so the shift below stays inside the type for any input length.
    uint32_t acc = 0;
    int bits = 0;
    std::vector<uint8_t> ret;
    const uint32_t maxv = (1u << tobits) - 1;
    const uint32_t max_acc = (1u << (frombits + tobits - 1)) - 1;

    for (const auto& value : data) {
        acc = ((acc << frombits) | value) & max_acc;
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

//! Size of the witness program of both address forms.
const size_t WITNESS_PROGRAM_SIZE = 32;

//! Witness versions that have an address form.
const uint8_t WITNESS_V1 = 1;
const uint8_t WITNESS_V6 = 6;

//! Bech32m address of a witness version and a 32-byte program. Empty for a
//! program of any other size.
std::string EncodeWitnessProgram(uint8_t version, const std::vector<uint8_t>& program, const std::string& hrp)
{
    if (program.size() != WITNESS_PROGRAM_SIZE) return std::string();

    std::vector<uint8_t> conv = ConvertBits(program, 8, 5, true);
    std::vector<uint8_t> enc;
    enc.push_back(version);
    enc.insert(enc.end(), conv.begin(), conv.end());
    return bech32::Encode(bech32::Encoding::BECH32M, hrp, enc);
}

//! Decode a Bech32m address of exactly this witness version, this
//! human-readable part and a 32-byte program. Both address forms decode
//! through here, so they share the checksum, prefix, version and length
//! checks. programRet is written only on success.
bool DecodeWitnessProgram(const std::string& str, const std::string& hrp, uint8_t version, std::vector<uint8_t>& programRet)
{
    bech32::DecodeResult dec = bech32::Decode(str);

    if (dec.encoding != bech32::Encoding::BECH32M || dec.hrp != hrp || dec.data.empty() || dec.data[0] != version)
        return false;

    std::vector<uint8_t> conv = ConvertBits(
        std::vector<uint8_t>(dec.data.begin() + 1, dec.data.end()),
        5, 8, false);
    if (conv.size() != WITNESS_PROGRAM_SIZE) return false;

    programRet = conv;
    return true;
}

} // namespace

std::string EncodeDestination(const CTxDestination& dest, const std::string& hrp)
{
    if (dest.which() == 3) { // WitnessV1ScriptHash
        const WitnessV1ScriptHash* witness_v1 = boost::get<WitnessV1ScriptHash>(&dest);
        if (witness_v1) {
            std::vector<uint8_t> data(witness_v1->begin(), witness_v1->end());
            return EncodeWitnessProgram(WITNESS_V1, data, hrp);
        }
    }

    // For other destination types, return empty string (legacy not supported)
    return "";
}

CTxDestination DecodeDestination(const std::string& str, const std::string& hrp)
{
    // Witness v1 (Dilithium) only. A witness v6 address is not a destination:
    // it decodes through DecodeWitnessV6Address.
    std::vector<uint8_t> program;
    if (DecodeWitnessProgram(str, hrp, WITNESS_V1, program)) {
        WitnessV1ScriptHash hash;
        std::copy(program.begin(), program.end(), hash.begin());
        return hash;
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

std::string EncodeWitnessV6Address(const std::vector<unsigned char>& program, const std::string& hrp)
{
    return EncodeWitnessProgram(WITNESS_V6, program, hrp);
}

bool DecodeWitnessV6Address(const std::string& str, const std::string& hrp, std::vector<unsigned char>& programRet)
{
    return DecodeWitnessProgram(str, hrp, WITNESS_V6, programRet);
}
