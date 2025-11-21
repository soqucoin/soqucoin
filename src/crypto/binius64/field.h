// Copyright (c) 2025 The Soqucoin Core developers
// Distributed under the MIT software license

#ifndef SOQUCOIN_CRYPTO_BINIUS64_FIELD_H
#define SOQUCOIN_CRYPTO_BINIUS64_FIELD_H


#include "uint256.h"
#include <array>
#include <cstdint>
#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

// Binius64 packed field arithmetic – ported from IrreducibleOSS/binius64 (October 2025 tag)
// Tower: GF(2) → GF(2^64) → GF(2^128) with irreducible x^128 + x^7 + 1
// All operations constant-time, no heap, Bitcoin-Core-style.
// This is the exact field used in the LatticeFold+ Dilithium batching benchmarks (Nethermind, Oct 2025).

class Binius64
{
public:
    alignas(32) std::array<uint64_t, 2> limbs; // low, high

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

    Binius64& operator*=(const Binius64& rhs) noexcept;

    Binius64 operator*(const Binius64& rhs) const noexcept
    {
        Binius64 res = *this;
        res *= rhs;
        return res;
    }

    static Binius64 batch_inverse(const std::array<Binius64, 64>& in) noexcept
    {
        // Montgomery batch inversion trick – O(n) field ops for 64 elements
        // Used heavily in packed sumcheck evaluation
        std::array<Binius64, 64> accum;
        accum[0] = in[0];
        for (int i = 1; i < 64; ++i)
            accum[i] = accum[i - 1] * in[i];

        Binius64 inv_accum = accum[63].mont_inverse();
        // We need to return something, but the signature in the prompt returns Binius64
        // and modifies 'in' in place (const_cast).
        // I'll follow the prompt's logic but we need to be careful with const_cast.
        // The prompt signature is: static Binius64 batch_inverse(const std::array<Binius64, 64>& in) noexcept
        // And implementation does: const_cast<Binius64&>(in[i]) = inv;
        // This implies 'in' is actually mutable or we are casting away const (dangerous but requested).

        // Re-implementing the loop from prompt:
        for (int i = 63; i >= 1; --i) {
            Binius64 inv = inv_accum * accum[i - 1];
            inv_accum = inv_accum * in[i];
            const_cast<Binius64&>(in[i]) = inv;
        }
        const_cast<Binius64&>(in[0]) = inv_accum;
        return inv_accum; // not used
    }

    Binius64 mont_inverse() const noexcept; // implemented in field.cpp
};

// Batch evaluation of multilinear polynomial over 8 variables (256 points → 1) used in folding round
Binius64 eval_multilinear_packed(const std::array<Binius64, 256>& poly, const std::array<Binius64, 8>& point) noexcept;

#endif // SOQUCOIN_CRYPTO_BINIUS64_FIELD_H
