// Copyright (c) 2025-2026 The Soqucoin Core developers
// Distributed under the MIT software license

// SECURITY NOTE: This file was completely rewritten as part of the Halborn
// Extension Audit remediation (SOQ-A001/A002/A003/A004). The original
// implementation contained 4 critical-severity field arithmetic bugs:
//   A001: Reducible trinomial x^128+x^7+1 (zero divisors exist)
//   A002: Wrong GFNI intrinsic (_mm_gf2p8mul_epi8 operates on GF(2^8), not GF(2^128))
//   A003: Single-pass reduction leaving 7 overflow bits unreduced
//   A004: mont_inverse() missing final squaring (computes a^(2^127-1) instead of a^(2^128-2))
//
// The correct field polynomial is the NIST SP 800-38D pentanomial:
//   p(x) = x^128 + x^7 + x^2 + x + 1
// This is the same polynomial used by AES-GCM (GHASH) across every major
// TLS implementation (OpenSSL, BoringSSL, NSS, mbedTLS, Go crypto/aes).

#include "crypto/binius64/field.h"
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

// ============================================================================
// GF(2^128) multiplication modulo x^128 + x^7 + x^2 + x + 1
// ============================================================================

Binius64& Binius64::operator*=(const Binius64& rhs) noexcept
{
#if defined(__PCLMUL__) && (defined(__x86_64__) || defined(_M_X64))
    // ========================================================================
    // PCLMULQDQ (Carry-Less Multiplication) Karatsuba path
    // Reference: Intel CLMUL White Paper, Algorithm 5 (Karatsuba method)
    // Available on all x86-64 CPUs since Westmere (2010) and AMD Bulldozer (2011)
    // ========================================================================

    __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(limbs.data()));
    __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(rhs.limbs.data()));

    // Karatsuba: 3 multiplications instead of 4
    // a = (a1, a0), b = (b1, b0)
    // c0 = a0 * b0  (low)
    // c2 = a1 * b1  (high)
    // c1 = (a0 + a1) * (b0 + b1) - c0 - c2  (middle, via XOR since GF(2))
    __m128i c0 = _mm_clmulepi64_si128(a, b, 0x00); // a0 * b0
    __m128i c2 = _mm_clmulepi64_si128(a, b, 0x11); // a1 * b1
    __m128i a_xor = _mm_xor_si128(a, _mm_srli_si128(a, 8)); // (a0^a1) in low 64
    __m128i b_xor = _mm_xor_si128(b, _mm_srli_si128(b, 8)); // (b0^b1) in low 64
    // We need to put a0^a1 into proper position for clmul
    // _mm_clmulepi64_si128 operates on [63:0] and [127:64]
    // Since we XOR'd, the result is in [63:0] of a_xor and b_xor
    __m128i c1 = _mm_clmulepi64_si128(a_xor, b_xor, 0x00); // (a0+a1)*(b0+b1)
    c1 = _mm_xor_si128(c1, c0);  // subtract c0
    c1 = _mm_xor_si128(c1, c2);  // subtract c2 → c1 is the middle 128 bits

    // Assemble 256-bit product: [c2_hi:c2_lo : c0_hi:c0_lo] with c1 added to middle
    // Product = c0 + c1*x^64 + c2*x^128
    // res[0..127]   = c0 XOR (c1_lo << 64)
    // res[128..255] = c2 XOR (c1_hi) XOR (c1_lo >> 0 ... shifted)
    __m128i c1_lo = _mm_slli_si128(c1, 8);  // c1_lo << 64 (into high half of 128)
    __m128i c1_hi = _mm_srli_si128(c1, 8);  // c1_hi >> 64 (into low half of 128)
    __m128i product_lo = _mm_xor_si128(c0, c1_lo);
    __m128i product_hi = _mm_xor_si128(c2, c1_hi);

    // ========================================================================
    // Reduction modulo x^128 + x^7 + x^2 + x + 1
    // For each bit at position 128+k in product_hi, we need to XOR bits at
    // positions k+7, k+2, k+1, k into the low 128 bits.
    //
    // This is equivalent to: product_lo ^= (H + H<<7 + H<<2 + H<<1)
    // where H = product_hi, but the shifts may overflow, requiring a second pass.
    // ========================================================================

    // First reduction pass: reduce bits 128..255 (product_hi)
    // H*1: XOR product_hi into product_lo directly
    // H*x: shift left by 1
    // H*x^2: shift left by 2
    // H*x^7: shift left by 7
    __m128i h = product_hi;

    // Compute the 4 shifted versions of H and their overflow bits
    // H << 1: overflow = 1 bit
    __m128i h_shl1 = _mm_or_si128(_mm_slli_epi64(h, 1),
                      _mm_srli_si128(_mm_slli_epi64(_mm_and_si128(h, _mm_set_epi64x(0, (int64_t)0xFFFFFFFFFFFFFFFFULL)), 63), 8));
    // More cleanly:
    // For a 128-bit left shift by N (N < 64):
    //   result_lo = h_lo << N
    //   result_hi = (h_hi << N) | (h_lo >> (64-N))
    //   overflow  = h_hi >> (64-N)  [these bits go above bit 255 after first pass]
    // For N=1:
    uint64_t h_lo, h_hi;
    std::memcpy(&h_lo, reinterpret_cast<const char*>(&h), 8);
    std::memcpy(&h_hi, reinterpret_cast<const char*>(&h) + 8, 8);

    // H * 1 (no shift)
    product_lo = _mm_xor_si128(product_lo, h);

    // H * x (shift left 1) — overflow: top 1 bit of h_hi
    uint64_t s1_lo = h_lo << 1;
    uint64_t s1_hi = (h_hi << 1) | (h_lo >> 63);
    uint64_t s1_overflow = h_hi >> 63; // 1 bit

    __m128i hs1 = _mm_set_epi64x(static_cast<int64_t>(s1_hi), static_cast<int64_t>(s1_lo));
    product_lo = _mm_xor_si128(product_lo, hs1);

    // H * x^2 (shift left 2) — overflow: top 2 bits of h_hi
    uint64_t s2_lo = h_lo << 2;
    uint64_t s2_hi = (h_hi << 2) | (h_lo >> 62);
    uint64_t s2_overflow = h_hi >> 62; // 2 bits

    __m128i hs2 = _mm_set_epi64x(static_cast<int64_t>(s2_hi), static_cast<int64_t>(s2_lo));
    product_lo = _mm_xor_si128(product_lo, hs2);

    // H * x^7 (shift left 7) — overflow: top 7 bits of h_hi
    uint64_t s7_lo = h_lo << 7;
    uint64_t s7_hi = (h_hi << 7) | (h_lo >> 57);
    uint64_t s7_overflow = h_hi >> 57; // 7 bits

    __m128i hs7 = _mm_set_epi64x(static_cast<int64_t>(s7_hi), static_cast<int64_t>(s7_lo));
    product_lo = _mm_xor_si128(product_lo, hs7);

    // Second reduction pass: the overflow bits (at most 7 bits from the x^7 shift)
    // represent terms x^128 through x^134, which must be reduced again.
    // overflow_combined = s1_overflow ^ s2_overflow ^ s7_overflow
    // These overflow bits need the same treatment: XOR at positions k, k+1, k+2, k+7
    // Since overflow is at most 7 bits, the second-pass shifts never overflow again.
    uint64_t ov = s1_overflow ^ s2_overflow ^ s7_overflow;
    // ov represents bits at positions 128..134 (at most 7 bits set)
    // Reduce: XOR ov at bit positions 0..6, 1..7, 2..8, 7..13
    uint64_t ov_reduced = ov ^ (ov << 1) ^ (ov << 2) ^ (ov << 7);

    // XOR into the low word of product_lo
    uint64_t result_lo, result_hi;
    std::memcpy(&result_lo, reinterpret_cast<const char*>(&product_lo), 8);
    std::memcpy(&result_hi, reinterpret_cast<const char*>(&product_lo) + 8, 8);
    result_lo ^= ov_reduced;

    limbs[0] = result_lo;
    limbs[1] = result_hi;
    return *this;

#else
    // ========================================================================
    // Portable fallback: bit-serial multiplication + two-pass reduction
    // Polynomial: x^128 + x^7 + x^2 + x + 1 (NIST SP 800-38D)
    // ========================================================================

    uint64_t a_lo = limbs[0];
    uint64_t a_hi = limbs[1];
    uint64_t b_lo = rhs.limbs[0];
    uint64_t b_hi = rhs.limbs[1];

    uint64_t res[4] = {0, 0, 0, 0}; // 256-bit product

    // Bit-serial multiplication over GF(2)
    // For each set bit i in a, XOR (b << i) into res
    auto add_shifted = [&](uint64_t b_l, uint64_t b_h, int shift) {
        if (shift < 64) {
            res[0] ^= b_l << shift;
            if (shift == 0) {
                res[1] ^= b_h;
            } else {
                res[1] ^= (b_l >> (64 - shift)) | (b_h << shift);
                res[2] ^= b_h >> (64 - shift);
            }
        } else {
            int s = shift - 64;
            res[1] ^= b_l << s;
            if (s == 0) {
                res[2] ^= b_h;
            } else {
                res[2] ^= (b_l >> (64 - s)) | (b_h << s);
                res[3] ^= b_h >> (64 - s);
            }
        }
    };

    for (int i = 0; i < 64; ++i) {
        if ((a_lo >> i) & 1) add_shifted(b_lo, b_hi, i);
    }
    for (int i = 0; i < 64; ++i) {
        if ((a_hi >> i) & 1) add_shifted(b_lo, b_hi, i + 64);
    }

    // ========================================================================
    // First reduction pass: reduce bits 128..255 (res[2], res[3])
    // x^128 ≡ x^7 + x^2 + x + 1 (mod p(x))
    // For each bit at position 128+k, XOR at positions k, k+1, k+2, k+7
    // ========================================================================
    uint64_t H_lo = res[2];
    uint64_t H_hi = res[3];

    // H * 1
    res[0] ^= H_lo;
    res[1] ^= H_hi;

    // H * x (left shift by 1)
    uint64_t s1_lo_p = H_lo << 1;
    uint64_t s1_hi_p = (H_hi << 1) | (H_lo >> 63);
    uint64_t s1_ov = H_hi >> 63;

    res[0] ^= s1_lo_p;
    res[1] ^= s1_hi_p;

    // H * x^2 (left shift by 2)
    uint64_t s2_lo_p = H_lo << 2;
    uint64_t s2_hi_p = (H_hi << 2) | (H_lo >> 62);
    uint64_t s2_ov = H_hi >> 62;

    res[0] ^= s2_lo_p;
    res[1] ^= s2_hi_p;

    // H * x^7 (left shift by 7)
    uint64_t s7_lo_p = H_lo << 7;
    uint64_t s7_hi_p = (H_hi << 7) | (H_lo >> 57);
    uint64_t s7_ov = H_hi >> 57;

    res[0] ^= s7_lo_p;
    res[1] ^= s7_hi_p;

    // ========================================================================
    // Second reduction pass: overflow bits from the first pass.
    // The shifts above discard the top N bits of H_hi (1, 2, and 7 bits
    // respectively). These correspond to terms x^128 through x^134 which
    // are still above the 128-bit boundary and must be reduced again.
    // Since overflow is at most 7 bits, the second pass produces no further
    // overflow (7 + 7 = 14 < 64, well within the low word).
    // SECURITY NOTE: This second pass was MISSING in the original code,
    // which is the root cause of SOQ-A003 (FIND-003).
    // ========================================================================
    uint64_t ov = s1_ov ^ s2_ov ^ s7_ov;
    uint64_t ov_reduced = ov ^ (ov << 1) ^ (ov << 2) ^ (ov << 7);
    res[0] ^= ov_reduced;

    limbs[0] = res[0];
    limbs[1] = res[1];
    return *this;
#endif
}

// ============================================================================
// Multiplicative inverse via Fermat's little theorem
// a^(-1) = a^(2^128 - 2) in GF(2^128)
//
// The exponent 2^128 - 2 in binary is: 1111...1110 (127 ones, 1 trailing zero)
// Algorithm: right-to-left square-and-multiply
//   - For bits 127 down to 1 (all '1'): multiply accumulator by base, then square base
//   - For bit 0 (the trailing '0'): square the accumulator (do NOT multiply)
//
// SECURITY NOTE: The original code was missing the final squaring (SOQ-A004/FIND-004).
// It computed a^(2^127-1) instead of a^(2^128-2). The final `res *= res` accounts
// for the trailing zero bit in the exponent.
// ============================================================================
Binius64 Binius64::mont_inverse() const noexcept
{
    // Handle zero input: inverse of zero is zero (convention)
    if (*this == zero()) return zero();

    Binius64 res = one();
    Binius64 base = *this;

    // Process bits 127 down to 1 (all are '1' in the exponent)
    for (int i = 0; i < 127; ++i) {
        res *= base;        // multiply (bit is 1)
        base *= base;       // square the base
    }

    // SECURITY NOTE (SOQ-A004): Final squaring for the trailing zero bit.
    // 2^128 - 2 = 2 * (2^127 - 1), so a^(2^128-2) = (a^(2^127-1))^2
    res *= res;

    return res;
}

// ============================================================================
// Multilinear polynomial evaluation (unchanged — not affected by audit)
// ============================================================================
Binius64 eval_multilinear_packed(const std::array<Binius64, 256>& poly, const std::array<Binius64, 8>& point) noexcept
{
    // O(n) evaluation via successive halving
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

// Placeholder for lattice-based commitment (future)
void BiniusPedersenCommit(const Binius64& value, const Binius64& blinding, Binius64& commitment)
{
    (void)value;
    (void)blinding;
    (void)commitment;
}
