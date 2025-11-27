// Copyright (c) 2025 The Soqucoin Core developers
// Adapted from Monero Project (BSD-3-Clause)
//
// Bulletproofs++ type adapters for Soqucoin
// Maps Monero's rct::key types to secp256k1 + Soqucoin primitives

#ifndef SOQUCOIN_ZK_RCT_TYPES_H
#define SOQUCOIN_ZK_RCT_TYPES_H

#include "../uint256.h"
#include <array>
#include <cstdint>
#include <vector>

namespace rct
{
// Monero uses 32-byte keys for all EC points and scalars
// We map these to uint256 and secp256k1 operations
typedef uint256 key;
typedef std::vector<key> keyV;
typedef std::vector<keyV> keyM;

// Bulletproofs++ structure (from Monero v0.18.3.3)
struct BulletproofPlus {
    rct::keyV V; // Vector commitments
    rct::key A;  // Aggregated commitment
    rct::key A1; // Round 1 commitment
    rct::key B;  // Challenge response
    rct::key r1; // Round 1 response
    rct::key s1; // Round 1 proof element
    rct::key d1; // Round 1 delta
    rct::keyV L; // Left curve points (log size)
    rct::keyV R; // Right curve points (log size)
};

// Basic operations (to be implemented using secp256k1)
key identity();
key scalarmultBase(const key& a);
key scalarmultKey(const key& P, const key& a);
void sc_add(key& res, const key& a, const key& b);
void sc_sub(key& res, const key& a, const key& b);
void sc_mul(key& res, const key& a, const key& b);
bool sc_check(const key& s);
key hash_to_scalar(const void* data, size_t length);

// Pedersen commitment: C = vG + rH
key commit(uint64_t amount, const key& mask);
} // namespace rct

#endif // SOQUCOIN_ZK_RCT_TYPES_H
