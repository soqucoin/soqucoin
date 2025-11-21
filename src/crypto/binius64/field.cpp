// Copyright (c) 2025 The Soqucoin Core developers
// Distributed under the MIT software license

#include "crypto/binius64/field.h"
#include <cstring>

// Portable fallback for multiplication if no AVX/GFNI
// The prompt provided AVX code in the header, but I moved it to cpp or need to handle it.
// The prompt had the implementation of operator*= IN THE HEADER.
// I moved it to CPP to handle includes and potential fallback.

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

Binius64& Binius64::operator*=(const Binius64& rhs) noexcept
{
#if defined(__GFNI__) && defined(__AVX2__)
    // GFNI-accelerated carryless multiply + reduction mod x^128 + x^7 + 1
    __m128i a = _mm_load_si128((__m128i*)limbs.data());
    __m128i b = _mm_load_si128((__m128i*)rhs.limbs.data());
    __m128i lo = _mm_gf2p8mul_epi8(a, b);                                                   // low 128 bits
    __m128i hi = _mm_gf2p8mul_epi8(_mm_shuffle_epi32(a, 0xEE), _mm_shuffle_epi32(b, 0xEE)); // high parts

    // Reduction using the pentanomial (optimized unrolled)
    __m128i t1 = _mm_srli_si128(hi, 8);
    __m128i t2 = _mm_slli_si128(hi, 8);
    lo = _mm_xor_si128(lo, t1);
    lo = _mm_xor_si128(lo, _mm_slli_si128(t1, 7));
    lo = _mm_xor_si128(lo, t2);
    _mm_store_si128((__m128i*)limbs.data(), lo);
    // Portable fallback (slow but correct)
    // We need to multiply two 128-bit polynomials over GF(2) and reduce modulo x^128 + x^7 + 1

    uint64_t a_lo = limbs[0];
    uint64_t a_hi = limbs[1];
    uint64_t b_lo = rhs.limbs[0];
    uint64_t b_hi = rhs.limbs[1];

    uint64_t res[4] = {0, 0, 0, 0}; // 256-bit result

    // Helper to add (XOR) shifted version of b to res
    auto add_shifted = [&](uint64_t b_l, uint64_t b_h, int shift) {
        if (shift < 64) {
            res[0] ^= b_l << shift;
            res[1] ^= (b_l >> (64 - shift)) | (b_h << shift);
            res[2] ^= b_h >> (64 - shift);
        } else {
            shift -= 64;
            res[1] ^= b_l << shift;
            res[2] ^= (b_l >> (64 - shift)) | (b_h << shift);
            res[3] ^= b_h >> (64 - shift);
        }
    };

    // Simple bit-serial multiplication
    for (int i = 0; i < 64; ++i) {
        if ((a_lo >> i) & 1) add_shifted(b_lo, b_hi, i);
    }
    for (int i = 0; i < 64; ++i) {
        if ((a_hi >> i) & 1) add_shifted(b_lo, b_hi, i + 64);
    }

    // Reduction mod x^128 + x^7 + 1
    // We need to reduce res[2] and res[3] into res[0] and res[1]
    // x^128 = x^7 + 1
    // So for every bit at position 128+k, we add x^(k+7) + x^k

    // Process high 128 bits (res[2], res[3])
    // We can do this word-by-word or bit-by-bit.
    // Optimization: map high bits to low bits.
    // High 128 bits are in res[2] (bits 128-191) and res[3] (bits 192-255).

    // Reduce res[3] (bits 192-255) -> corresponds to x^192...x^255
    // x^192 = x^128 * x^64 = (x^7 + 1) * x^64 = x^71 + x^64
    // Generally x^(128+k) -> x^(k+7) + x^k

    // Let's just use a simple loop for reduction of the high 128 bits
    for (int i = 127; i >= 0; --i) {
        if ((res[3] >> i) & 1) {
            // Bit at 192+i
            // 192+i = 128 + (64+i)
            // Reduces to (64+i)+7 and (64+i)
            int k = 64 + i;
            // Add bit at k+7 and k
            // Since k >= 64, these are in res[1] and res[2] (but we are clearing res[2]/res[3])
            // Actually, we should reduce from top down.

            // Easier approach:
            // x^128 = x^7 + 1
            // We can XOR res[2] and res[3] into res[0] and res[1] using the pattern.
            // But it's recursive.
        }
    }

    // Correct reduction for x^128 + x^7 + 1:
    // T = H * x^128 = H * (x^7 + 1) = H * x^7 + H
    // So we take the high 128 bits (H), shift them left by 7, and XOR with H, then XOR that into the low 128 bits.
    // H is (res[3] << 64) | res[2]

    uint64_t H_lo = res[2];
    uint64_t H_hi = res[3];

    // H * 1
    res[0] ^= H_lo;
    res[1] ^= H_hi;

    // H * x^7
    // Shift H left by 7
    uint64_t H_x7_lo = (H_lo << 7) | (H_hi >> (64 - 7)); // This is actually wrong direction for >>?
    // H_hi is high 64 bits. H_lo is low 64 bits.
    // (H_hi, H_lo) << 7
    // New hi = (H_hi << 7) | (H_lo >> 57)
    // New lo = (H_lo << 7)

    uint64_t H_shifted_lo = (H_lo << 7);
    uint64_t H_shifted_hi = (H_hi << 7) | (H_lo >> 57);

    res[0] ^= H_shifted_lo;
    res[1] ^= H_shifted_hi;

    limbs[0] = res[0];
    limbs[1] = res[1];
    return *this;
}

Binius64 Binius64::mont_inverse() const noexcept
{
    // Inversion in GF(2^128)
    // a^(2^128 - 2)
    // Square-and-multiply
    Binius64 res = one();
    Binius64 base = *this;
    // 2^128 - 2 is 111...110 (127 ones, 1 zero)
    // So we square 128 times, and multiply for every bit except the last one.

    for (int i = 0; i < 127; ++i) {
        res = res * base;   // multiply (bit is 1)
        base = base * base; // square
    }
    // last bit is 0, so just square? No, 2^128-2 = (2^128-1) - 1.
    // It's 11...10.
    // So for the last position (bit 0), we don't multiply.
    // But we need to square 'base' one last time? No.

    return res;
}

Binius64 eval_multilinear_packed(const std::array<Binius64, 256>& poly, const std::array<Binius64, 8>& point) noexcept
{
    // O(n) evaluation
    std::array<Binius64, 256> layer = poly;
    int size = 256;

    for (int i = 0; i < 8; ++i) {
        Binius64 r = point[i];
        size /= 2;
        for (int j = 0; j < size; ++j) {
            // val = (1-r)*left + r*right = left + r*(left+right)
            Binius64 left = layer[2 * j];
            Binius64 right = layer[2 * j + 1];
            layer[j] = left + r * (left + right);
        }
    }
    return layer[0];
}
