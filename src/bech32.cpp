// Copyright (c) 2017, 2021 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bech32.h"

#include <vector>

namespace bech32
{

namespace
{

typedef std::vector<uint8_t> data;

const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
    1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
    1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1};

uint32_t EncodingConstant(Encoding encoding)
{
    if (encoding == Encoding::BECH32) return 1;
    if (encoding == Encoding::BECH32M) return 0x2bc830a3;
    return 0;
}

uint32_t PolyMod(const data& v)
{
    uint32_t c = 1;
    for (const auto v_i : v) {
        uint8_t c0 = c >> 25;
        c = ((c & 0x1ffffff) << 5) ^ v_i;
        if (c0 & 1) c ^= 0x3b6a57b2;
        if (c0 & 2) c ^= 0x26508e6d;
        if (c0 & 4) c ^= 0x1ea119fa;
        if (c0 & 8) c ^= 0x3d4233dd;
        if (c0 & 16) c ^= 0x2a1462b3;
    }
    return c;
}

inline unsigned char LowerCase(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (c - 'A') + 'a' : c;
}

data ExpandHRP(const std::string& hrp)
{
    data ret;
    ret.reserve(hrp.size() * 2 + 1);
    for (size_t i = 0; i < hrp.size(); ++i) {
        unsigned char c = hrp[i];
        ret.push_back(c >> 5);
    }
    ret.push_back(0);
    for (size_t i = 0; i < hrp.size(); ++i) {
        unsigned char c = hrp[i];
        ret.push_back(c & 31);
    }
    return ret;
}

Encoding VerifyChecksum(const std::string& hrp, const data& values)
{
    data enc = ExpandHRP(hrp);
    enc.insert(enc.end(), values.begin(), values.end());
    uint32_t res = PolyMod(enc);
    if (res == EncodingConstant(Encoding::BECH32)) return Encoding::BECH32;
    if (res == EncodingConstant(Encoding::BECH32M)) return Encoding::BECH32M;
    return Encoding::INVALID;
}

data CreateChecksum(Encoding encoding, const std::string& hrp, const data& values)
{
    data enc = ExpandHRP(hrp);
    enc.insert(enc.end(), values.begin(), values.end());
    enc.resize(enc.size() + 6);
    uint32_t mod = PolyMod(enc) ^ EncodingConstant(encoding);
    data ret;
    ret.resize(6);
    for (size_t i = 0; i < 6; ++i) {
        ret[i] = (mod >> (5 * (5 - i))) & 31;
    }
    return ret;
}

} // namespace

std::string Encode(Encoding encoding, const std::string& hrp, const data& values)
{
    std::string lower_hrp;
    for (size_t i = 0; i < hrp.size(); ++i) {
        lower_hrp += LowerCase(hrp[i]);
    }

    data checksum = CreateChecksum(encoding, lower_hrp, values);
    data combined = values;
    combined.insert(combined.end(), checksum.begin(), checksum.end());
    std::string ret = lower_hrp + "1";
    ret.reserve(ret.size() + combined.size());
    for (const auto c : combined) {
        ret += CHARSET[c];
    }
    return ret;
}

DecodeResult Decode(const std::string& str)
{
    bool lower = false, upper = false;
    for (size_t i = 0; i < str.size(); ++i) {
        unsigned char c = str[i];
        if (c >= 'a' && c <= 'z')
            lower = true;
        else if (c >= 'A' && c <= 'Z')
            upper = true;
        else if (c < 33 || c > 126)
            return {};
    }
    if (lower && upper) return {};
    size_t pos = str.rfind('1');
    if (str.size() > 90 || pos == str.npos || pos == 0 || pos + 7 > str.size()) {
        return {};
    }
    data values;
    values.resize(str.size() - 1 - pos);
    for (size_t i = 0; i < str.size() - 1 - pos; ++i) {
        unsigned char c = str[i + pos + 1];
        int8_t rev = CHARSET_REV[c];
        if (rev == -1) {
            return {};
        }
        values[i] = rev;
    }
    std::string hrp;
    for (size_t i = 0; i < pos; ++i) {
        hrp += LowerCase(str[i]);
    }
    Encoding result = VerifyChecksum(hrp, values);
    if (result == Encoding::INVALID) return {};
    return {result, std::move(hrp), data(values.begin(), values.end() - 6)};
}

} // namespace bech32
