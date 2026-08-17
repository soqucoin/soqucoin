#pragma once

#include <vector>
#include <array>
#include <tuple>

using valtype = std::vector<unsigned char>;

// ML-DSA-44 (FIPS 204) key and signature sizes.
//
// ⛔ PATBasePrivateKey WAS 2528, WHICH IS THE WRONG PARAMETER SET.
// 2528 is the ROUND-3 Dilithium2 secret-key size; FIPS-204 ML-DSA-44 is 2560
// (the extra 32 bytes are the tr field growing from 32 to 64). The vendored
// implementation is FIPS-204 — pqcrystals_dilithium2_SECRETKEYBYTES is 2560,
// SEEDBYTES 32 / TRBYTES 64 / RNDBYTES 32 — so this typedef was 32 bytes short.
//
// It caused no corruption only because all three of these aliases are currently
// UNUSED; every live path sizes its buffers from the implementation's own
// constants (see keys.cpp). But a type named PATBasePrivateKey, sized for a
// superseded parameter set, sitting in pat/types.h, is a landmine waiting for
// someone to use it for exactly what its name says — a 32-byte overflow on the
// first keypair() call.
//
// ⚠️ These are now bound to the implementation by static_assert in keys.cpp.
// Do NOT hardcode a new literal here without adding the matching assertion; the
// point is that a parameter-set change must break the build, not the heap.
using PATBasePublicKey = std::array<unsigned char, 1312>;   // pk
using PATBasePrivateKey = std::array<unsigned char, 2560>;  // sk (was 2528: round-3)
using PATBaseSignature = std::array<unsigned char, 2420>;   // sig

struct CDilithiumPublicKey {
    valtype v;
    CDilithiumPublicKey() = default;
    CDilithiumPublicKey(const valtype& v_) : v(v_) {}
};

struct CDilithiumPrivateKey {
    valtype v;
    CDilithiumPrivateKey() = default;
    CDilithiumPrivateKey(const valtype& v_) : v(v_) {}
};

