#pragma once

#include <vector>
#include <array>

using valtype = std::vector<unsigned char>;

using PATBasePublicKey = std::array<unsigned char, 1312>;
using PATBasePrivateKey = std::array<unsigned char, 2528>;
using PATBaseSignature = std::array<unsigned char, 2420>;

struct CDilithiumPublicKey {
    valtype v;
    CDilithiumPublicKey() = default;
    CDilithiumPublicKey(const valtype& v_) : v(v_) {}
};

struct CDilithiumPrivateKey {
    valtype v;
    CDilithiumPrivateKey() = default;
    CDilithiumPrivateKey(const valtype& v_) : v(v_) {}
};

