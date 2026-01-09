// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file blake2b.cpp
 * @brief BLAKE2b implementation based on RFC 7693
 *
 * This is a minimal, self-contained implementation optimized for
 * correctness and auditability. No external dependencies.
 *
 * Reference: https://www.rfc-editor.org/rfc/rfc7693
 */

#include "crypto/blake2b.h"
#include <algorithm>
#include <cstring>

// BLAKE2b initialization vector (same as SHA-512)
static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

// Sigma permutation for rounds
static const uint8_t blake2b_sigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

// Rotate right
static inline uint64_t rotr64(uint64_t x, int n)
{
    return (x >> n) | (x << (64 - n));
}

// Load 64-bit little-endian
static inline uint64_t load64_le(const uint8_t* p)
{
    return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

// Store 64-bit little-endian
static inline void store64_le(uint8_t* p, uint64_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

// G mixing function
#define G(r, i, a, b, c, d)                         \
    do {                                            \
        a = a + b + m[blake2b_sigma[r][2 * i + 0]]; \
        d = rotr64(d ^ a, 32);                      \
        c = c + d;                                  \
        b = rotr64(b ^ c, 24);                      \
        a = a + b + m[blake2b_sigma[r][2 * i + 1]]; \
        d = rotr64(d ^ a, 16);                      \
        c = c + d;                                  \
        b = rotr64(b ^ c, 63);                      \
    } while (0)

void CBLAKE2b::Compress(const uint8_t* block)
{
    uint64_t m[16];
    uint64_t v[16];

    // Load message block
    for (int i = 0; i < 16; ++i) {
        m[i] = load64_le(block + i * 8);
    }

    // Initialize working vector
    for (int i = 0; i < 8; ++i) {
        v[i] = h[i];
        v[i + 8] = blake2b_IV[i];
    }

    v[12] ^= t[0]; // Low word of offset
    v[13] ^= t[1]; // High word of offset
    v[14] ^= f[0]; // Finalization flag
    v[15] ^= f[1];

    // 12 rounds of mixing
    for (int r = 0; r < 12; ++r) {
        G(r, 0, v[0], v[4], v[8], v[12]);
        G(r, 1, v[1], v[5], v[9], v[13]);
        G(r, 2, v[2], v[6], v[10], v[14]);
        G(r, 3, v[3], v[7], v[11], v[15]);
        G(r, 4, v[0], v[5], v[10], v[15]);
        G(r, 5, v[1], v[6], v[11], v[12]);
        G(r, 6, v[2], v[7], v[8], v[13]);
        G(r, 7, v[3], v[4], v[9], v[14]);
    }

    // Finalize state
    for (int i = 0; i < 8; ++i) {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

CBLAKE2b::CBLAKE2b(size_t outlen_)
{
    outlen = (outlen_ > 64) ? 64 : (outlen_ < 1 ? 1 : outlen_);
    Reset();
}

CBLAKE2b& CBLAKE2b::Reset()
{
    // Initialize state with IV XORed with parameter block
    for (int i = 0; i < 8; ++i) {
        h[i] = blake2b_IV[i];
    }

    // Parameter block: outlen in first byte, keylen=0, fanout=1, depth=1
    h[0] ^= 0x01010000ULL ^ outlen;

    t[0] = t[1] = 0;
    f[0] = f[1] = 0;
    buflen = 0;
    memset(buf, 0, sizeof(buf));

    return *this;
}

CBLAKE2b& CBLAKE2b::Write(const unsigned char* data, size_t len)
{
    const uint8_t* in = data;

    while (len > 0) {
        // If buffer is full, compress it
        if (buflen == 128) {
            t[0] += 128;
            if (t[0] < 128) t[1]++; // Overflow
            Compress(buf);
            buflen = 0;
        }

        // Fill buffer
        size_t fill = std::min(len, (size_t)(128 - buflen));
        memcpy(buf + buflen, in, fill);
        buflen += fill;
        in += fill;
        len -= fill;
    }

    return *this;
}

void CBLAKE2b::Finalize(unsigned char* hash)
{
    // Update counter with remaining bytes
    t[0] += buflen;
    if (t[0] < buflen) t[1]++;

    // Set finalization flag
    f[0] = ~(uint64_t)0;

    // Pad remaining buffer with zeros
    memset(buf + buflen, 0, 128 - buflen);

    // Final compression
    Compress(buf);

    // Output hash (little-endian)
    uint8_t buffer[64];
    for (int i = 0; i < 8; ++i) {
        store64_le(buffer + i * 8, h[i]);
    }
    memcpy(hash, buffer, outlen);

    // Clear sensitive data
    memset(h, 0, sizeof(h));
    memset(buf, 0, sizeof(buf));
}

void BLAKE2b_160(unsigned char* out, const unsigned char* in, size_t inlen)
{
    CBLAKE2b hasher(20);
    hasher.Write(in, inlen);
    hasher.Finalize(out);
}

void BLAKE2b_256(unsigned char* out, const unsigned char* in, size_t inlen)
{
    CBLAKE2b hasher(32);
    hasher.Write(in, inlen);
    hasher.Finalize(out);
}
