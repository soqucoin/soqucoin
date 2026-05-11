// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license
//
// liblatticebp — Flat C API for Lattice-BP++ Cryptographic Primitives
//
// This is the standalone C interface to the Lattice-BP++ post-quantum
// privacy system. Designed for FFI consumption by mobile wallets
// (SoquShield via dart:ffi) and third-party integrations.
//
// Architecture: C API → C++ internals (commitment, range_proof, ring_signature, stealth_address)
//
// Patent: Soqucoin Labs Inc. — Provisional Application (Lattice-BP Hybrid)
//         World-first mobile post-quantum ZK proof generation.
//
// SECURITY NOTES:
//   - All secret material is cleansed via lbp_secure_free()
//   - No data-dependent branches in verify paths (constant-time)
//   - Fiat-Shamir transcript binds to sighash + pubkey_hash (SOQ-A005)
//   - Randomness expanded via HKDF-SHA256 from 32-byte seed (SOQ-D004)
//   - All deserialization validates sizes before access
//

#ifndef SOQUCOIN_LATTICEBP_CAPI_H
#define SOQUCOIN_LATTICEBP_CAPI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ═══════════════════════════════════════════════════════════════════
//  Version and Constants
// ═══════════════════════════════════════════════════════════════════

#define LBP_VERSION_MAJOR    1
#define LBP_VERSION_MINOR    0
#define LBP_VERSION_PATCH    0

/** Lattice parameters (aligned with Dilithium ML-DSA-44) */
#define LBP_RING_DIM         256       // N — polynomial ring dimension
#define LBP_MODULUS          8380417   // Q — prime modulus
#define LBP_MODULE_RANK      4        // K — module rank
#define LBP_RANGE_BITS       64       // Range proof: v ∈ [0, 2^64)
#define LBP_DEFAULT_RING_SIZE 11      // Decoy ring size (Monero-style)

/** Buffer sizes (bytes) — callers must allocate at least this much */
#define LBP_COMMITMENT_SIZE     8192   // K * N * sizeof(int64_t)
#define LBP_PROOF_MAX_SIZE      16384  // ~12KB actual, 16KB max
#define LBP_KEY_IMAGE_SIZE      2048   // N * sizeof(int64_t)
#define LBP_RING_SIG_MAX_SIZE   32768  // Depends on ring size (~26KB for 11)
#define LBP_STEALTH_PK_SIZE     8192   // K * N * sizeof(int64_t)
#define LBP_TX_PUBKEY_SIZE      2048   // N * sizeof(int64_t)
#define LBP_VIEW_KEY_SIZE       2048   // RingElement serialized
#define LBP_SPEND_KEY_SIZE      2048   // RingElement serialized
#define LBP_PUBLIC_KEY_SIZE     8192   // K * N * sizeof(int64_t)
#define LBP_PARAMS_SEED_SIZE    32     // Consensus seed for PublicParams

// ═══════════════════════════════════════════════════════════════════
//  Error Codes
// ═══════════════════════════════════════════════════════════════════

#define LBP_OK                  0    // Success
#define LBP_ERR_INVALID_PARAM  -1    // Invalid parameter (null, out of range)
#define LBP_ERR_BUFFER_TOO_SMALL -2  // Output buffer too small
#define LBP_ERR_PROOF_FAILED   -3    // Proof generation failed (RNG, rejection)
#define LBP_ERR_VERIFY_FAILED  -4    // Verification failed
#define LBP_ERR_DESERIALIZE    -5    // Deserialization error
#define LBP_ERR_RNG_FAILURE    -6    // Secure random number generation failed
#define LBP_ERR_NORM_EXCEEDED  -7    // Norm bound exceeded (rejection sampling)
#define LBP_ERR_INTERNAL       -99   // Internal error

// ═══════════════════════════════════════════════════════════════════
//  Library Lifecycle
// ═══════════════════════════════════════════════════════════════════

/**
 * Get library version string (e.g., "1.0.0").
 */
const char* lbp_version(void);

/**
 * Initialize the library. Must be called before any other function.
 * Sets up consensus public parameters from the given seed.
 *
 * @param params_seed  32-byte consensus seed for deterministic PublicParams generation
 * @return LBP_OK on success
 */
int lbp_init(const uint8_t params_seed[LBP_PARAMS_SEED_SIZE]);

/**
 * Clean up library resources. Call when done.
 */
void lbp_cleanup(void);

/**
 * Securely free memory (memset_s + free). Use for all secret material.
 *
 * @param ptr  Pointer to memory to cleanse
 * @param len  Number of bytes to cleanse
 */
void lbp_secure_free(void* ptr, size_t len);

// ═══════════════════════════════════════════════════════════════════
//  1. Commitment — Hide transaction amounts
// ═══════════════════════════════════════════════════════════════════

/**
 * Generate a Lattice commitment hiding a value.
 *
 * C = value * A + randomness * S  (Ring-LWE Pedersen)
 *
 * @param value           The amount to commit to (SOQ satoshis or USDSOQ cents)
 * @param randomness      Blinding factor (from lbp_sample_randomness)
 * @param rand_len        Length of randomness buffer (must be >= LBP_VIEW_KEY_SIZE)
 * @param commitment_out  Output buffer (must be >= LBP_COMMITMENT_SIZE)
 * @param commit_len      [in/out] Size of output buffer; on return, actual size
 * @return LBP_OK on success
 */
int lbp_commit(
    uint64_t value,
    const uint8_t* randomness, size_t rand_len,
    uint8_t* commitment_out, size_t* commit_len
);

/**
 * Verify a commitment opening.
 *
 * @param value           The claimed value
 * @param randomness      The claimed blinding factor
 * @param rand_len        Length of randomness
 * @param commitment      The commitment to verify against
 * @param commit_len      Length of commitment
 * @return LBP_OK if commitment matches, LBP_ERR_VERIFY_FAILED otherwise
 */
int lbp_commit_verify(
    uint64_t value,
    const uint8_t* randomness, size_t rand_len,
    const uint8_t* commitment, size_t commit_len
);

// ═══════════════════════════════════════════════════════════════════
//  2. Range Proof — Prove amount ∈ [0, 2^64)
// ═══════════════════════════════════════════════════════════════════

/**
 * Generate a Lattice-BP++ range proof.
 *
 * Proves that the committed value is in [0, 2^64) without revealing
 * the value. Uses Fiat-Shamir with sighash + pubkey_hash binding
 * (SOQ-A005 audit hardening).
 *
 * @param value          The value to prove range for
 * @param randomness     Blinding factor used in commitment
 * @param rand_len       Length of randomness
 * @param commitment     The commitment (from lbp_commit)
 * @param commit_len     Length of commitment
 * @param sighash        32-byte transaction sighash (external binding)
 * @param pubkey_hash    32-byte UTXO pubkey hash (external binding)
 * @param proof_out      Output buffer (must be >= LBP_PROOF_MAX_SIZE)
 * @param proof_len      [in/out] Size of output buffer; on return, actual proof size
 * @return LBP_OK on success
 */
int lbp_range_prove(
    uint64_t value,
    const uint8_t* randomness, size_t rand_len,
    const uint8_t* commitment, size_t commit_len,
    const uint8_t sighash[32],
    const uint8_t pubkey_hash[32],
    uint8_t* proof_out, size_t* proof_len
);

/**
 * Verify a Lattice-BP++ range proof (constant-time).
 *
 * @param proof          Serialized range proof
 * @param proof_len      Length of proof
 * @param commitment     The commitment being proved
 * @param commit_len     Length of commitment
 * @param sighash        32-byte transaction sighash
 * @param pubkey_hash    32-byte UTXO pubkey hash
 * @return LBP_OK if valid, LBP_ERR_VERIFY_FAILED otherwise
 */
int lbp_range_verify(
    const uint8_t* proof, size_t proof_len,
    const uint8_t* commitment, size_t commit_len,
    const uint8_t sighash[32],
    const uint8_t pubkey_hash[32]
);

// ═══════════════════════════════════════════════════════════════════
//  3. Ring Signature — Sender anonymity (MLSAG)
// ═══════════════════════════════════════════════════════════════════

/**
 * Sign a message using a ring of public keys (MLSAG for multi-input).
 *
 * The signer proves they own one of the keys in the ring without
 * revealing which one. A key image is produced for double-spend prevention.
 *
 * @param message        32-byte message to sign (transaction hash)
 * @param ring_pks       Array of serialized public keys (ring_count * LBP_PUBLIC_KEY_SIZE)
 * @param ring_count     Number of public keys in the ring (including real)
 * @param real_index     Index of the signer's key in the ring
 * @param private_key    Signer's private key (LBP_SPEND_KEY_SIZE bytes)
 * @param pk_len         Length of private key
 * @param sig_out        Output buffer for signature (>= LBP_RING_SIG_MAX_SIZE)
 * @param sig_len        [in/out] Size of sig buffer; on return, actual size
 * @param key_image_out  Output buffer for key image (>= LBP_KEY_IMAGE_SIZE)
 * @param ki_len         [in/out] Size of key image buffer; on return, actual size
 * @return LBP_OK on success
 */
int lbp_ring_sign(
    const uint8_t message[32],
    const uint8_t* ring_pks, size_t ring_count,
    size_t real_index,
    const uint8_t* private_key, size_t pk_len,
    uint8_t* sig_out, size_t* sig_len,
    uint8_t* key_image_out, size_t* ki_len
);

/**
 * Verify a ring signature.
 *
 * @param message      32-byte message that was signed
 * @param ring_pks     Array of serialized public keys
 * @param ring_count   Number of public keys in the ring
 * @param signature    Serialized ring signature
 * @param sig_len      Length of signature
 * @param key_image    Key image from the signature
 * @param ki_len       Length of key image
 * @return LBP_OK if valid, LBP_ERR_VERIFY_FAILED otherwise
 */
int lbp_ring_verify(
    const uint8_t message[32],
    const uint8_t* ring_pks, size_t ring_count,
    const uint8_t* signature, size_t sig_len,
    const uint8_t* key_image, size_t ki_len
);

// ═══════════════════════════════════════════════════════════════════
//  4. Stealth Address — One-time recipient addresses
// ═══════════════════════════════════════════════════════════════════

/**
 * Generate a stealth address for a recipient.
 *
 * Creates a one-time public key that only the recipient can link to
 * their wallet (using their view key) and spend (using their spend key).
 *
 * @param view_pk         Recipient's public view key (LBP_PUBLIC_KEY_SIZE)
 * @param spend_pk        Recipient's public spend key (LBP_PUBLIC_KEY_SIZE)
 * @param one_time_pk_out Output: one-time public key (>= LBP_STEALTH_PK_SIZE)
 * @param otpk_len        [in/out] Size of one_time_pk buffer; on return, actual size
 * @param tx_pub_key_out  Output: transaction public key (>= LBP_TX_PUBKEY_SIZE)
 * @param txpk_len        [in/out] Size of tx_pub_key buffer; on return, actual size
 * @return LBP_OK on success
 */
int lbp_stealth_generate(
    const uint8_t* view_pk, size_t vpk_len,
    const uint8_t* spend_pk, size_t spk_len,
    uint8_t* one_time_pk_out, size_t* otpk_len,
    uint8_t* tx_pub_key_out, size_t* txpk_len
);

/**
 * Scan a stealth address to check if output belongs to us.
 *
 * @param one_time_pk     One-time public key from the transaction output
 * @param otpk_len        Length of one_time_pk
 * @param tx_pub_key      Transaction public key (R)
 * @param txpk_len        Length of tx_pub_key
 * @param view_key        Our private view key (LBP_VIEW_KEY_SIZE)
 * @param vk_len          Length of view key
 * @param spend_pk        Our public spend key (LBP_PUBLIC_KEY_SIZE)
 * @param spk_len         Length of spend_pk
 * @return LBP_OK if output belongs to us, LBP_ERR_VERIFY_FAILED otherwise
 */
int lbp_stealth_scan(
    const uint8_t* one_time_pk, size_t otpk_len,
    const uint8_t* tx_pub_key, size_t txpk_len,
    const uint8_t* view_key, size_t vk_len,
    const uint8_t* spend_pk, size_t spk_len
);

/**
 * Recover the one-time private key for spending a stealth output.
 *
 * @param tx_pub_key       Transaction public key (R)
 * @param txpk_len         Length of tx_pub_key
 * @param view_key         Our private view key
 * @param vk_len           Length of view key
 * @param spend_key        Our private spend key
 * @param sk_len           Length of spend key
 * @param one_time_sk_out  Output: one-time private key (>= LBP_SPEND_KEY_SIZE)
 * @param otsk_len         [in/out] Size of output buffer; on return, actual size
 * @return LBP_OK on success
 */
int lbp_stealth_recover_key(
    const uint8_t* tx_pub_key, size_t txpk_len,
    const uint8_t* view_key, size_t vk_len,
    const uint8_t* spend_key, size_t sk_len,
    uint8_t* one_time_sk_out, size_t* otsk_len
);

// ═══════════════════════════════════════════════════════════════════
//  5. Key Derivation — Privacy keys from BIP-39 seed
// ═══════════════════════════════════════════════════════════════════

/**
 * Derive privacy view key and spend key from a master seed.
 *
 * Uses HKDF-SHA256 with domain separators:
 *   - View key:  "soqucoin.privacy.view.v1"
 *   - Spend key: "soqucoin.privacy.spend.v1"
 *
 * Same seed + same domain = same keys (deterministic).
 * Compatible with L1 node derivation chain.
 *
 * @param master_seed     BIP-39 master seed (32 or 64 bytes)
 * @param seed_len        Length of master seed
 * @param view_key_out    Output: private view key (>= LBP_VIEW_KEY_SIZE)
 * @param vk_len          [in/out] Size of view key buffer; on return, actual size
 * @param spend_key_out   Output: private spend key (>= LBP_SPEND_KEY_SIZE)
 * @param sk_len          [in/out] Size of spend key buffer; on return, actual size
 * @return LBP_OK on success
 */
int lbp_derive_privacy_keys(
    const uint8_t* master_seed, size_t seed_len,
    uint8_t* view_key_out, size_t* vk_len,
    uint8_t* spend_key_out, size_t* sk_len
);

/**
 * Derive public keys from private keys (view and spend).
 *
 * @param view_key        Private view key (LBP_VIEW_KEY_SIZE)
 * @param vk_len          Length of view key
 * @param spend_key       Private spend key (LBP_SPEND_KEY_SIZE)
 * @param sk_len          Length of spend key
 * @param view_pk_out     Output: public view key (>= LBP_PUBLIC_KEY_SIZE)
 * @param vpk_len         [in/out] Size of view pk buffer; on return, actual size
 * @param spend_pk_out    Output: public spend key (>= LBP_PUBLIC_KEY_SIZE)
 * @param spk_len         [in/out] Size of spend pk buffer; on return, actual size
 * @return LBP_OK on success
 */
int lbp_derive_public_keys(
    const uint8_t* view_key, size_t vk_len,
    const uint8_t* spend_key, size_t sk_len,
    uint8_t* view_pk_out, size_t* vpk_len,
    uint8_t* spend_pk_out, size_t* spk_len
);

// ═══════════════════════════════════════════════════════════════════
//  6. Sampling — Secure randomness for blinding factors
// ═══════════════════════════════════════════════════════════════════

/**
 * Sample secure randomness for commitment blinding factors.
 *
 * Uses CSPRNG with HKDF-SHA256 expansion (SOQ-D004 compliant).
 * The output is a serialized RingElement suitable for use as
 * a blinding factor in lbp_commit().
 *
 * @param randomness_out  Output buffer (>= LBP_VIEW_KEY_SIZE / 2048 bytes)
 * @param len             Requested length (must be LBP_VIEW_KEY_SIZE)
 * @return LBP_OK on success, LBP_ERR_RNG_FAILURE on CSPRNG error
 */
int lbp_sample_randomness(uint8_t* randomness_out, size_t len);

// ═══════════════════════════════════════════════════════════════════
//  7. LatticeFold Accumulation — Batch range proofs into single proof
// ═══════════════════════════════════════════════════════════════════

/**
 * Accumulate multiple Lattice-BP++ range proofs into a single
 * LatticeFold proof (witness v3, already audited by Halborn).
 *
 * This uses the ALWAYS_ACTIVE LatticeFold verifier to batch
 * multiple v4 range proofs into a near-constant-size v3 proof.
 * Both primitives use the same lattice parameter family (N=256,
 * Q=8380417, K=4), ensuring no mixed trust assumptions.
 *
 * @param proofs          Array of serialized range proofs (concatenated)
 * @param proof_count     Number of proofs in the array
 * @param proof_sizes     Array of individual proof sizes
 * @param commitments     Array of serialized commitments (concatenated)
 * @param commit_count    Number of commitments (must equal proof_count)
 * @param commit_sizes    Array of individual commitment sizes
 * @param folded_out      Output: folded proof (>= LBP_PROOF_MAX_SIZE)
 * @param folded_len      [in/out] Size of output buffer; on return, actual size
 * @return LBP_OK on success
 */
int lbp_latticefold_accumulate(
    const uint8_t* proofs, size_t proof_count, const size_t* proof_sizes,
    const uint8_t* commitments, size_t commit_count, const size_t* commit_sizes,
    uint8_t* folded_out, size_t* folded_len
);

/**
 * Verify a folded (accumulated) proof via LatticeFold v3 verifier.
 *
 * @param folded_proof    Serialized folded proof
 * @param folded_len      Length of folded proof
 * @param commitments     Array of original commitments (concatenated)
 * @param commit_count    Number of commitments
 * @param commit_sizes    Array of individual commitment sizes
 * @return LBP_OK if valid, LBP_ERR_VERIFY_FAILED otherwise
 */
int lbp_latticefold_verify(
    const uint8_t* folded_proof, size_t folded_len,
    const uint8_t* commitments, size_t commit_count, const size_t* commit_sizes
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // SOQUCOIN_LATTICEBP_CAPI_H
