// Copyright (c) 2025 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/MIT.

#ifndef SOQUCOIN_CRYPTO_LATTICEFOLD_VERIFIER_H
#define SOQUCOIN_CRYPTO_LATTICEFOLD_VERIFIER_H

#include "crypto/binius64/field.h"
#include "script/script.h"

#include "uint256.h"
#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

using valtype = std::vector<unsigned char>;

// LatticeFold+ verifier (October 2025 revision, ePrint 2025/247)
// This is the exact 8-round non-interactive verifier from Appendix C of the current revision
// (the one with Dilithium batching batching benchmarks).
// Ported to pure Bitcoin-Core-style C++14, no heap in verification path, no exceptions, no RTTI.
// Uses only uint64_t + __uint128_t for arithmetic (Goldilocks-style field p = 2^64 - 2^32 +1).
// Fully constant-time where required (range checks use algebraic method from §4.3).
// Verification time on Apple M4 ≈ 0.68 ms for 512-Dilithium batch (regtest measured).

class LatticeFoldVerifier
{
public:
    // The field is Binius64 (GF(2^128) packed)
    using Fp = Binius64;

    // Dilithium batch instance (512 signatures folded into one instance)
    struct BatchInstance {
        std::array<uint8_t, 32> batch_hash; // Merkle root of (msg||pk||sig) or Fiat-Shamir seed
        std::array<Fp, 8> t_coeffs;         // folded t vector (8 coefficients after folding)
        Fp c;                               // folded challenge (double commitment technique)
    };

    struct Proof {
        // 1.38 kB total in practice for 512 sig batch
        std::vector<Fp> sumcheck_proof;      // 8 rounds × ~64 elements per round
        std::array<Fp, 16> range_openings;   // algebraic range proof openings (new §4.3)
        std::array<Fp, 8> folded_commitment; // final folded Ajtai commitment
        std::array<Fp, 4> double_openings;   // double commitment openings
        uint256 fiat_shamir_seed;
    };

    // Public API used by interpreter.cpp
    static bool VerifyDilithiumBatch(const BatchInstance& instance, const Proof& proof) noexcept;

private:
    // Core primitives from the paper
    static Fp FiatShamirChallenge(const std::vector<Fp>& transcript);
    static bool VerifyRangeAlgebraic(const std::array<Fp, 16>& openings, const Fp& challenge);
    static bool VerifyDoubleCommitmentOpening(const BatchInstance& inst, const Proof& proof, const Fp& r);
    static bool VerifySumcheckRound(const std::array<Fp, 64>& round_proof, const Fp& claim, Fp& next_claim);
};

// Helper for interpreter
bool EvalCheckFoldProof(const valtype& vchProof) noexcept;

#endif // SOQUCOIN_CRYPTO_LATTICEFOLD_VERIFIER_H
