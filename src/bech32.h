// Copyright (c) 2017, 2021 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BECH32_H
#define BITCOIN_BECH32_H

#include <stdint.h>
#include <string>
#include <vector>

namespace bech32
{

enum class Encoding {
    INVALID,
    BECH32,
    BECH32M,
};

std::string Encode(Encoding spec, const std::string& hrp, const std::vector<uint8_t>& values);

struct DecodeResult {
    Encoding encoding;
    std::string hrp;
    std::vector<uint8_t> data;

    DecodeResult() : encoding(Encoding::INVALID) {}
    DecodeResult(Encoding enc, std::string h, std::vector<uint8_t> d) : encoding(enc), hrp(std::move(h)), data(std::move(d)) {}
};

DecodeResult Decode(const std::string& str);

} // namespace bech32

#endif // BITCOIN_BECH32_H
