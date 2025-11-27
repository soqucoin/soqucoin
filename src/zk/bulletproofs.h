// Copyright (c) 2025 The Soqucoin Core developers
// Adapted from Elements Project secp256k1-zkp
// Distributed under the MIT software license

#ifndef SOQUCOIN_ZK_BULLETPROOFS_H
#define SOQUCOIN_ZK_BULLETPROOFS_H

#include "amount.h"
#include "uint256.h"
#include <cstdint>
#include <vector>

// Include secp256k1-zkp headers directly (not forward declare to avoid typedef conflicts)
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_generator.h"

namespace zk
{

// Pedersen commitment structure (33 bytes compressed point)
struct Commitment {
    std::vector<unsigned char> data; // 33 bytes

    Commitment() : data(33, 0) {}
    Commitment(const std::vector<unsigned char>& d) : data(d) {}

    bool operator==(const Commitment& other) const { return data == other.data; }
};

// Range Proof structure (~674 bytes for 64-bit range, Bulletproofs++ can be ~700-1200 bytes)
struct RangeProof {
    std::vector<unsigned char> data;

    RangeProof() {}
    RangeProof(const std::vector<unsigned char>& d) : data(d) {}
};

// Initialize secp256k1 context for range proofs (call once at startup)
bool InitRangeProofContext();

// Shutdown context (call at cleanup)
void ShutdownRangeProofContext();

// Generate a Pedersen commitment for a value with a blinding factor
// C = v*G + r*H (where G, H are generators)
// Returns true on success
bool GenerateCommitment(CAmount value, const uint256& blinding, Commitment& commitment_out);

// Generate a range proof that value is in [0, 2^64)
// Uses secp256k1-zkp Bulletproofs implementation
// proof size approx 674 bytes for 64-bit range
// MUST use constant-time blinding factor generation (GetStrongRandBytes)
bool GenRangeProof(CAmount value, const uint256& blinding, const uint256& nonce, const Commitment& commitment, RangeProof& proof_out);

// Verify a range proof for a commitment
// Returns true if proof is valid (value is in [0, 2^64))
// This is the consensus-critical function - MUST be constant-time
bool VerifyRangeProof(const RangeProof& proof, const Commitment& commitment);

// Rewind a range proof to recover the value and blinding (for wallet use, not consensus)
// Returns true if rewind succeeded
bool RewindRangeProof(const RangeProof& proof, const Commitment& commitment, const uint256& nonce, CAmount& value_out, uint256& blinding_out);

} // namespace zk

#endif // SOQUCOIN_ZK_BULLETPROOFS_H
