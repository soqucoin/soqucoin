// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_CRYPTO_BLAKE2B_H
#define SOQUCOIN_CRYPTO_BLAKE2B_H

/**
 * @file blake2b.h
 * @brief BLAKE2b cryptographic hash function implementation
 *
 * Implements BLAKE2b as specified in RFC 7693.
 * Primary use: Address hashing with 160-bit (20 byte) output for compact
 * post-quantum addresses.
 *
 * Why BLAKE2b-160?
 * - 3-5x faster than SHA-256 for large inputs (Dilithium keys are 1,312 bytes)
 * - 160 bits provides 80-bit collision resistance (sufficient for addresses)
 * - Stronger quantum security margins than SHA-256
 * - Compatible with HKDF for L2 key derivation
 *
 * @see RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code
 */

#include <cstdint>
#include <cstdlib>

/** BLAKE2b hash class with configurable output length */
class CBLAKE2b
{
private:
    uint64_t h[8];    // State
    uint64_t t[2];    // Counter
    uint64_t f[2];    // Finalization flags
    uint8_t buf[128]; // Buffer
    size_t buflen;    // Buffer length
    size_t outlen;    // Digest length

    void Compress(const uint8_t* block);

public:
    static const size_t OUTPUT_SIZE_160 = 20; // 160 bits
    static const size_t OUTPUT_SIZE_256 = 32; // 256 bits
    static const size_t OUTPUT_SIZE_512 = 64; // 512 bits (max)
    static const size_t BLOCKSIZE = 128;

    /**
     * @brief Construct BLAKE2b hasher with specified output length
     * @param outlen Output length in bytes (1-64, default 20 for addresses)
     */
    explicit CBLAKE2b(size_t outlen = OUTPUT_SIZE_160);

    /** Reset to initial state */
    CBLAKE2b& Reset();

    /** Write data to be hashed */
    CBLAKE2b& Write(const unsigned char* data, size_t len);

    /** Finalize and produce digest */
    void Finalize(unsigned char* hash);
};

/** Convenience function for 160-bit (address) hashing */
void BLAKE2b_160(unsigned char* out, const unsigned char* in, size_t inlen);

/** Convenience function for 256-bit hashing */
void BLAKE2b_256(unsigned char* out, const unsigned char* in, size_t inlen);

#endif // SOQUCOIN_CRYPTO_BLAKE2B_H
