// Copyright (c) 2024-2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-ARCH-001: Privacy Layer Consensus Types
// Design Log: DL-PRIVACY-INTEGRATION-ARCHITECTURE.md
//
// This header defines consensus-level types for the privacy layer:
//   - LatticeKeyImageHash: 32-byte key-image identifier for double-spend detection
//   - ViewKeyData: optional auditor-transparency payload for confidential outputs
//
// These types bridge the crypto primitives (crypto/latticebp/) to the consensus
// layer (validation.cpp, coins.h, txdb.h). They are BIP9-gated behind
// DEPLOYMENT_LATTICEBP and only active on stagenet/testnet.

#ifndef SOQUCOIN_CONSENSUS_PRIVACY_H
#define SOQUCOIN_CONSENSUS_PRIVACY_H

#include "serialize.h"
#include "uint256.h"
#include "hash.h"

#include <cstdint>
#include <vector>

// =========================================================================
// LatticeKeyImageHash — Double-spend detection identifier
// =========================================================================
// A 32-byte SHA256 hash of the serialized lattice key image. This is what
// gets stored in the spent-key-image set (DB prefix 'K' in txdb.cpp).
//
// The full key image is ~2KB (LatticeParams::N * sizeof(int64_t) = 256*8).
// Hashing to 32 bytes provides collision resistance while being efficient
// for LevelDB storage and in-memory set lookups.
//
// Usage in ConnectBlock():
//   1. Extract key images from confidential TX witness data
//   2. Hash each: ki_hash = SHA256(key_image.serialize())
//   3. Check: if HaveKeyImage(ki_hash) → reject (double-spend)
//   4. Store: WriteKeyImage(ki_hash, block_height)
//
// Usage in DisconnectBlock():
//   1. Extract key images from the block being disconnected
//   2. EraseKeyImage(ki_hash) for each

struct LatticeKeyImageHash
{
    uint256 hash;

    LatticeKeyImageHash() : hash() {}
    explicit LatticeKeyImageHash(const uint256& h) : hash(h) {}

    //! Compute the key-image hash from raw serialized key-image bytes
    static LatticeKeyImageHash FromSerializedKeyImage(const std::vector<uint8_t>& serialized)
    {
        uint256 h;
        CHash256().Write(serialized.data(), serialized.size()).Finalize((unsigned char*)&h);
        return LatticeKeyImageHash(h);
    }

    bool operator==(const LatticeKeyImageHash& other) const { return hash == other.hash; }
    bool operator!=(const LatticeKeyImageHash& other) const { return hash != other.hash; }
    bool operator<(const LatticeKeyImageHash& other) const { return hash < other.hash; }

    bool IsNull() const { return hash.IsNull(); }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hash);
    }
};

// =========================================================================
// ViewKeyData — Auditor/regulator transparency payload
// =========================================================================
// Optional data attached to a confidential output that enables a designated
// auditor to view the transaction amount and destination without the
// spend key.
//
// When a user creates a confidential transaction, they can optionally
// encrypt the output amount and memo under the auditor's view key.
// The auditor can then:
//   1. Decrypt the amount using their view key
//   2. Verify the commitment matches: Commit(amount, blinding) == C
//   3. Report compliance without being able to spend
//
// Wire format (variable-length, only present when nVisibility == 0x01):
//   [1 byte]   version (0x01 = v1)
//   [32 bytes] tx_public_key (sender's ephemeral DH key)
//   [N bytes]  encrypted_amount (AEAD-sealed under shared secret)
//   [32 bytes] amount_commitment_check (first 32 bytes of the commitment)
//
// SECURITY: The encrypted_amount uses ChaCha20-Poly1305 with key derived
// from HKDF(view_key || tx_public_key || "soqucoin.view.v1"). The MAC
// prevents tampering; the commitment_check enables the auditor to verify
// the decrypted amount matches the on-chain commitment.

struct ViewKeyData
{
    uint8_t nVersion;                           // Protocol version (0x01)
    std::vector<uint8_t> tx_public_key;         // 32 bytes: sender's ephemeral key
    std::vector<uint8_t> encrypted_amount;      // Variable: AEAD-encrypted amount+blinding
    std::vector<uint8_t> amount_commitment_check; // 32 bytes: commitment verification

    ViewKeyData() : nVersion(0) {}

    bool IsNull() const { return nVersion == 0; }

    //! Estimated serialized size in bytes
    size_t SerializedSize() const {
        if (IsNull()) return 0;
        return 1 + tx_public_key.size() + encrypted_amount.size()
               + amount_commitment_check.size() + 12; // 12 = VARINT overhead
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        if (nVersion > 0) {
            READWRITE(tx_public_key);
            READWRITE(encrypted_amount);
            READWRITE(amount_commitment_check);
        }
    }
};

#endif // SOQUCOIN_CONSENSUS_PRIVACY_H
