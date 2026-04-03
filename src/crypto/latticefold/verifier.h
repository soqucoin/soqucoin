// Copyright (c) 2025-2026 The Soqucoin Core developers
// Distributed under the MIT software license

// SECURITY NOTE: This header was redesigned as part of the Halborn Extension
// Audit remediation (SOQ-A005/FIND-005). The original BatchInstance accepted
// all verification data from the untrusted proof blob with no external binding.
// The redesigned verifier:
//   1. Uses multi-element witness stack (proof, pubkey_hash, sighash from checker)
//   2. Derives consensus matrix A deterministically from SHAKE-128
//   3. Recomputes batch_hash independently from witness Dilithium signatures
//   4. Follows the same UTXO-commitment pattern as OP_CHECKDILITHIUMSIG

#ifndef SOQUCOIN_CRYPTO_LATTICEFOLD_VERIFIER_H
#define SOQUCOIN_CRYPTO_LATTICEFOLD_VERIFIER_H

#include "crypto/binius64/field.h"
#include "uint256.h"

#include <array>
#include <cstdint>
#include <vector>

using valtype = std::vector<unsigned char>;

// ============================================================================
// Consensus matrix A — deterministically derived from SHAKE-128
// Domain separator: "soqucoin-latticefold-v1"
// ============================================================================

// Matrix A dimensions for the LatticeFold+ protocol (Boneh & Chen §4.1)
// 4 rows × 8 columns of GF(2^128) elements = 32 elements total
// These are computed once at startup from SHAKE-128 and are identical on all nodes.
static constexpr size_t MATRIX_A_ROWS = 4;
static constexpr size_t MATRIX_A_COLS = 8;

// LatticeFold+ verifier (redesigned April 2026, Halborn remediation)
// Based on ePrint 2025/247, Appendix C (October 2025 revision)
// with UTXO binding per Soqucoin consensus requirements.
class LatticeFoldVerifier
{
public:
    using Fp = Binius64;

    // SECURITY NOTE (SOQ-A005): Redesigned BatchInstance with external binding.
    // Previously, all fields were deserialized from the untrusted proof blob.
    // Now:
    //   - sighash: comes from BaseSignatureChecker (transaction context)
    //   - pubkey_hash: comes from scriptPubKey (UTXO commitment)
    //   - batch_hash: recomputed by consensus from Dilithium signatures in witness
    //   - t_coeffs/c: still from proof blob (verified against commitments)
    struct BatchInstance {
        uint256 sighash;                        // from checker — transaction context binding
        std::array<uint8_t, 32> pubkey_hash;    // from scriptPubKey — UTXO commitment
        std::array<uint8_t, 32> batch_hash;     // RECOMPUTED from witness sigs, not from proof
        std::array<Fp, 8> t_coeffs;             // folded t vector (8 coefficients after folding)
        Fp c;                                   // folded challenge (double commitment technique)
    };

    struct Proof {
        // Wire Format Specification (v2 — with external binding):
        // -----------------------------------------------------------------------------------------
        // | Field             | Size (Bytes) | Description                                        |
        // |-------------------|--------------|----------------------------------------------------| 
        // | t_coeffs          | 128          | 8 * 16 bytes (folded t vector)                     |
        // | c                 | 16           | folded challenge                                   |
        // | Sumcheck Proof    | N * 16       | N elements (N % 64 == 0), 8 rounds * 64 elements   |
        // | Range Openings    | 256          | 16 * 16 bytes (algebraic range proof)              |
        // | Folded Commitment | 128          | 8 * 16 bytes (final Ajtai commitment)              |
        // | Double Openings   | 64           | 4 * 16 bytes (double commitment openings)          |
        // | Fiat-Shamir Seed  | 32           | Final seed for non-malleability                    |
        // -----------------------------------------------------------------------------------------
        // Header = 128 + 16 = 144 bytes (batch_hash removed — now recomputed)
        // Footer = 256 + 128 + 64 + 32 = 480 bytes
        // Min = 144 + 480 = 624 bytes
        // Standard (8 rounds) = 144 + 8192 + 480 = 8816 bytes

        std::vector<Fp> sumcheck_proof;         // 8 rounds × 64 elements per round
        std::array<Fp, 16> range_openings;      // algebraic range proof openings (§4.3)
        std::array<Fp, 8> folded_commitment;    // final folded Ajtai commitment
        std::array<Fp, 4> double_openings;      // double commitment openings
        uint256 fiat_shamir_seed;
    };

    // Public API used by interpreter.cpp
    // SECURITY NOTE: Now takes the consensus matrix A as a parameter instead of
    // using hardcoded values. The matrix is derived at startup from SHAKE-128.
    static bool VerifyDilithiumBatch(
        const BatchInstance& instance,
        const Proof& proof,
        const std::array<std::array<Fp, MATRIX_A_COLS>, MATRIX_A_ROWS>& matrixA) noexcept;

    // Initialize consensus matrix A from SHAKE-128 with domain separation
    // Called once at startup, result cached globally
    static void DeriveConsensusMatrixA(
        std::array<std::array<Fp, MATRIX_A_COLS>, MATRIX_A_ROWS>& matrixA) noexcept;

    // Compute batch_hash from a set of Dilithium signatures (independent recomputation)
    static void ComputeBatchHash(
        const std::vector<valtype>& dilithium_sigs,
        std::array<uint8_t, 32>& out_hash) noexcept;

private:
    static Fp FiatShamirChallenge(const std::vector<Fp>& transcript);
    static bool VerifyRangeAlgebraic(const std::array<Fp, 16>& openings, const Fp& challenge);
    static bool VerifyDoubleCommitmentOpening(
        const BatchInstance& inst,
        const Proof& proof,
        const Fp& r,
        const std::array<std::array<Fp, MATRIX_A_COLS>, MATRIX_A_ROWS>& matrixA);
    static bool VerifySumcheckRound(const std::array<Fp, 64>& round_proof, const Fp& claim, Fp& next_claim);
};

// OP_CHECKFOLDPROOF (0xfc) — multi-element stack version
// SECURITY NOTE (SOQ-A005): The old single-blob API is replaced.
// The new API takes sighash and pubkey_hash from the consensus layer.
bool EvalCheckFoldProof(
    const valtype& vchProof,
    const uint256& sighash,
    const std::array<uint8_t, 32>& pubkey_hash,
    const std::vector<valtype>& dilithium_sigs) noexcept;

#endif // SOQUCOIN_CRYPTO_LATTICEFOLD_VERIFIER_H
