#pragma once

#include <array>
#include <crypto/binius/utils.h>
#include <cstdint>

namespace binius
{

// Binary field elements packed into 64-bit words
// We support GF(2^1), GF(2^8), GF(2^64)

// GF(2^1) is just bits.
// GF(2^8) uses the AES polynomial 0x11B (x^8 + x^4 + x^3 + x + 1) usually,
// but Binius often uses a tower construction.
// The prompt implies "packed GF(2^4) and GF(2^8) towers".
// We will implement a standard tower:
// GF(2^1)
// GF(2^2) = GF(2)[X] / (X^2 + X + 1)
// GF(2^4) = GF(2^2)[Y] / (Y^2 + Y + X)
// GF(2^8) = GF(2^4)[Z] / (Z^2 + Z + X*Y)  <-- Example tower, need to match Binius spec exactly if possible.
// However, for "packed field arithmetic", we often just treat them as bits in a larger word.

// For this implementation, we will define the types and basic operations.

struct BinaryField1b {
    uint64_t val; // 64 packed elements
};

struct BinaryField8b {
    uint64_t val; // 8 packed elements
};

struct BinaryField64b {
    uint64_t val; // 1 packed element
};

class PackedField
{
public:
    // Basic arithmetic on packed elements
    static BinaryField64b Add(BinaryField64b a, BinaryField64b b);
    static BinaryField64b Mul(BinaryField64b a, BinaryField64b b);
    static BinaryField64b Inv(BinaryField64b a);

    // Packed operations (SIMD-like within the register)
    static BinaryField8b Add(BinaryField8b a, BinaryField8b b);
    static BinaryField8b Mul(BinaryField8b a, BinaryField8b b); // Element-wise

    // Conversions
    static BinaryField64b FromUint64(uint64_t v) { return {v}; }
    static uint64_t ToUint64(BinaryField64b v) { return v.val; }
};

} // namespace binius
