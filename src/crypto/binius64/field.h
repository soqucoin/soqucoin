// Copyright (c) 2025-2026 The Soqucoin Core developers
// Distributed under the MIT software license

#ifndef SOQUCOIN_CRYPTO_BINIUS64_FIELD_H
#define SOQUCOIN_CRYPTO_BINIUS64_FIELD_H

#include "uint256.h"
#include <array>
#include <cstdint>

// Binius64 packed field arithmetic – GF(2^128) with NIST pentanomial
// Polynomial: x^128 + x^7 + x^2 + x + 1 (same as AES-GCM GHASH, NIST SP 800-38D)
// All operations constant-time, no heap, Bitcoin-Core-style.
//
// SECURITY NOTE: The original polynomial x^128+x^7+1 was REDUCIBLE (SOQ-A001/FIND-001).
// The NIST pentanomial is irreducible and has 15+ years of deployment in production TLS.

class Binius64
{
public:
    alignas(16) std::array<uint64_t, 2> limbs; // low, high

    Binius64() = default;
    constexpr Binius64(uint64_t lo, uint64_t hi = 0) : limbs{{lo, hi}} {}

    static const Binius64 zero() noexcept { return Binius64(0, 0); }
    static const Binius64 one() noexcept { return Binius64(1, 0); }

    bool operator==(const Binius64& other) const noexcept
    {
        return limbs[0] == other.limbs[0] && limbs[1] == other.limbs[1];
    }

    bool operator!=(const Binius64& other) const noexcept
    {
        return !(*this == other);
    }

    Binius64& operator+=(const Binius64& rhs) noexcept
    {
        limbs[0] ^= rhs.limbs[0];
        limbs[1] ^= rhs.limbs[1];
        return *this;
    }

    Binius64 operator+(const Binius64& rhs) const noexcept
    {
        Binius64 res = *this;
        res += rhs;
        return res;
    }

    Binius64& operator*=(const Binius64& rhs) noexcept; // implemented in field.cpp

    Binius64 operator*(const Binius64& rhs) const noexcept
    {
        Binius64 res = *this;
        res *= rhs;
        return res;
    }

    // SECURITY NOTE (SOQ-A006/FIND-006): batch_inverse() previously accepted
    // const& and used const_cast to write back results — undefined behavior.
    // Changed to mutable reference. Callers must pass a non-const array.
    static void batch_inverse(std::array<Binius64, 64>& in) noexcept
    {
        // Montgomery batch inversion trick – O(n) field ops for 64 elements
        // Uses a single expensive mont_inverse() call instead of 64.
        std::array<Binius64, 64> accum;
        accum[0] = in[0];
        for (int i = 1; i < 64; ++i)
            accum[i] = accum[i - 1] * in[i];

        Binius64 inv_accum = accum[63].mont_inverse();

        // Backward sweep: recover individual inverses
        for (int i = 63; i >= 1; --i) {
            Binius64 inv = inv_accum * accum[i - 1];
            inv_accum *= in[i];
            in[i] = inv;  // Direct write — no const_cast needed
        }
        in[0] = inv_accum;
    }

    Binius64 mont_inverse() const noexcept; // implemented in field.cpp
};

// Batch evaluation of multilinear polynomial over 8 variables (256 points → 1)
// Used in folding round sumcheck verification
Binius64 eval_multilinear_packed(const std::array<Binius64, 256>& poly, const std::array<Binius64, 8>& point) noexcept;

#endif // SOQUCOIN_CRYPTO_BINIUS64_FIELD_H
