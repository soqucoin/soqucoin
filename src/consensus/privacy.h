// Copyright (c) 2024-2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SOQ-ARCH-001: Privacy Layer Consensus Types
// Design Log: DL-PRIVACY-INTEGRATION-ARCHITECTURE.md
//
// This header defines consensus-level types for the SoquObscura privacy layer:
//   - LatticeKeyImageHash: 32-byte key-image identifier for double-spend detection
//
// The auditor-transparency payload formerly declared here (ViewKeyData) was
// deleted in WI-4; its replacement is soquobscura::Disclosure in
// consensus/soquobscura/disclosure.h. See the note further down and
// doc/design/DL-SOQUOBSCURA-VE-CONSENSUS-PLAN.md.
//
// These types bridge the crypto primitives to the consensus layer
// (validation.cpp, coins.h, txdb.h) and are BIP9-gated, active on
// stagenet/testnet only.
//
// NAMING: "Lattice-BP++" refers to the SUPERSEDED design (ring signatures,
// stealth addresses, hand-rolled range proofs), which Part I of the scope
// document found unsound. The current system is SoquObscura. See
// doc/design/DL-SOQUOBSCURA-NAMING-POLICY.md.

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
// (removed) ViewKeyData — Auditor/regulator transparency payload
// =========================================================================
// DELETED 2026-08-16 (WI-4). See doc/design/DL-SOQUOBSCURA-VE-CONSENSUS-PLAN.md.
//
// The struct that stood here was ChaCha20-Poly1305 over a key derived by HKDF
// from a Diffie-Hellman shared secret. The ratified scope document
// (DL-LATTICEBP-STATE-ANALYSIS-2026-07-18 section II.3) says of exactly this
// design that it "is replaced wholesale" by Module-LWE verifiable encryption.
// Four reasons it had to go rather than be extended:
//
//   1. it was documented as OPTIONAL, so it carried no compliance force;
//   2. nothing in the validation path referenced it;
//   3. it had no proof of correct encryption — only a 32-byte commitment hint
//      an auditor could check AFTER decrypting, which consensus cannot use
//      because consensus never decrypts;
//   4. its key agreement was Diffie-Hellman, which Shor breaks. An auditor
//      payload whose confidentiality rests on classical DH is a
//      harvest-now-decrypt-later target inside a post-quantum chain.
//
// Replacement: soquobscura::Disclosure in consensus/soquobscura/disclosure.h —
// Module-LWE verifiable encryption, MANDATORY and consensus-enforced for
// confidential USDSOQ (Tier A). Asset-typed: Tier B (confidential SOQ) uses
// user-held keys and is user-optional, so the rule keys off asset type rather
// than off IsConfidential() alone.

#endif // SOQUCOIN_CONSENSUS_PRIVACY_H
