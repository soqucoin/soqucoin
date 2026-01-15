// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// Lattice-BP++: Ring Signatures for Privacy
// Stage 3 R&D - Lattice-based Ring Signature Implementation
//

#ifndef SOQUCOIN_CRYPTO_LATTICEBP_RING_SIGNATURE_H
#define SOQUCOIN_CRYPTO_LATTICEBP_RING_SIGNATURE_H

#include "commitment.h"
#include <array>
#include <stdint.h>
#include <vector>

namespace latticebp
{

/**
 * Ring Signature Parameters
 *
 * Inspired by Monero's ring signatures but adapted for lattice-based
 * cryptography. Uses Module-SIS for unforgeability and Ring-LWE for
 * anonymity within the ring.
 */
struct RingParams {
    static constexpr size_t DEFAULT_RING_SIZE = 11; // 11 decoys (like Monero)
    static constexpr size_t MIN_RING_SIZE = 3;
    static constexpr size_t MAX_RING_SIZE = 32;

    // Key image size (prevents double-spend)
    static constexpr size_t KEY_IMAGE_SIZE = LatticeParams::N * sizeof(int64_t);
};

/**
 * Lattice Public Key
 *
 * Post-quantum public key derived from Dilithium but optimized
 * for ring signature operations.
 */
class LatticePublicKey
{
public:
    std::array<RingElement, LatticeParams::K> key;

    // Derive from Dilithium public key
    static LatticePublicKey fromDilithium(const std::vector<uint8_t>& dilithium_pk);

    // Generate stealth address (one-time key for recipient)
    static LatticePublicKey deriveStealthAddress(
        const LatticePublicKey& recipient_pk,
        const std::array<uint8_t, 32>& tx_random);

    // Serialization
    std::vector<uint8_t> serialize() const;
    static LatticePublicKey deserialize(const std::vector<uint8_t>& data);

    bool operator==(const LatticePublicKey& other) const;
};

/**
 * Key Image
 *
 * Unique identifier for each spent output. Prevents double-spending
 * while maintaining anonymity (cannot link to specific public key).
 */
class KeyImage
{
public:
    RingElement image;

    // Generate key image from private key and public key
    static KeyImage generate(
        const RingElement& private_key,
        const LatticePublicKey& public_key);

    // Check if key image has been seen before (double-spend detection)
    // Note: Actual check happens in consensus layer
    bool operator==(const KeyImage& other) const;

    // Serialization
    std::vector<uint8_t> serialize() const;
    static KeyImage deserialize(const std::vector<uint8_t>& data);
};

/**
 * Lattice Ring Signature (LSAG-style)
 *
 * Linkable Spontaneous Anonymous Group signature adapted for
 * lattice-based cryptography. Proves ownership of one key in a ring
 * without revealing which one.
 */
class LatticeRingSignature
{
public:
    // Ring signature components
    KeyImage key_image;
    std::vector<RingElement> responses; // One per ring member
    RingElement challenge_seed;         // Initial challenge

    /**
     * Sign a message using one key from a ring of public keys.
     *
     * @param message      Message to sign (typically transaction hash)
     * @param ring         Vector of public keys (decoys + real)
     * @param real_index   Index of the signer's key in the ring
     * @param private_key  Signer's private key
     * @return Ring signature proving ownership
     */
    static LatticeRingSignature sign(
        const std::array<uint8_t, 32>& message,
        const std::vector<LatticePublicKey>& ring,
        size_t real_index,
        const RingElement& private_key);

    /**
     * Verify ring signature.
     *
     * @param message  Message that was signed
     * @param ring     Ring of public keys
     * @return true if signature is valid
     */
    bool verify(
        const std::array<uint8_t, 32>& message,
        const std::vector<LatticePublicKey>& ring) const;

    /**
     * Batch verify multiple ring signatures.
     * Uses LatticeFold+ for efficient verification of many signatures.
     */
    static bool batchVerify(
        const std::vector<LatticeRingSignature>& signatures,
        const std::vector<std::array<uint8_t, 32> >& messages,
        const std::vector<std::vector<LatticePublicKey> >& rings);

    // Ring size
    size_t ringSize() const { return responses.size(); }

    // Serialization
    std::vector<uint8_t> serialize() const;
    static LatticeRingSignature deserialize(const std::vector<uint8_t>& data);

    // Estimated size in bytes
    size_t size() const;
};

/**
 * MLSAG: Multi-Layered Linkable Spontaneous Anonymous Group Signature
 *
 * Extension of ring signatures for transactions with multiple inputs.
 * Each input has its own ring, but they share a common challenge for
 * atomicity.
 */
class MLSAG
{
public:
    std::vector<KeyImage> key_images;
    std::vector<std::vector<RingElement> > responses; // [input][ring_member]
    RingElement challenge_seed;

    /**
     * Sign multiple inputs atomically.
     */
    static MLSAG sign(
        const std::array<uint8_t, 32>& message,
        const std::vector<std::vector<LatticePublicKey> >& rings,
        const std::vector<size_t>& real_indices,
        const std::vector<RingElement>& private_keys);

    /**
     * Verify MLSAG signature.
     */
    bool verify(
        const std::array<uint8_t, 32>& message,
        const std::vector<std::vector<LatticePublicKey> >& rings) const;

    // Number of inputs
    size_t inputCount() const { return key_images.size(); }

    // Serialization
    std::vector<uint8_t> serialize() const;
    static MLSAG deserialize(const std::vector<uint8_t>& data);
};

} // namespace latticebp

#endif // SOQUCOIN_CRYPTO_LATTICEBP_RING_SIGNATURE_H
