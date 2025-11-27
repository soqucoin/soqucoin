// Copyright (c) 2025 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_ZK_BULLETPROOFS_H
#define SOQUCOIN_ZK_BULLETPROOFS_H

#include "../amount.h"
#include "../uint256.h"
#include <cstdint>
#include <vector>

namespace zk
{

// Binius64 field element is 64-bit
using FieldElement = uint64_t;

// Commitment structure (Pedersen-like over Lattice/Binius)
// C = v*G + r*H where G, H are generator matrices/vectors
// For v1, we use a simplified 32-byte commitment (hash-based or lattice-vector)
struct Commitment {
    std::vector<unsigned char> data; // 32 bytes

    Commitment() : data(32, 0) {}
    Commitment(const std::vector<unsigned char>& d) : data(d) {}

    bool operator==(const Commitment& other) const { return data == other.data; }
};

// Range Proof structure (~1.2kB)
struct RangeProof {
    std::vector<unsigned char> data;

    RangeProof() {}
    RangeProof(const std::vector<unsigned char>& d) : data(d) {}
};

// Generate a commitment for a value with a blinding factor
Commitment Commit(CAmount value, const uint256& blinding);

// Generate a range proof that value is in [0, 2^64)
// proof size approx 1.2kB
RangeProof GenRangeProof(CAmount value, const uint256& blinding, const Commitment& commitment);

// Verify a range proof for a commitment
bool VerifyRangeProof(const RangeProof& proof, const Commitment& commitment);

} // namespace zk

#endif // SOQUCOIN_ZK_BULLETPROOFS_H
