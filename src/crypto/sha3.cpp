// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Based on https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
// by Markku-Juhani O. Saarinen <mjos@iki.fi>

#include <crypto/common.h>
#include <crypto/sha3.h>

#include <algorithm>
#include <bit>
#include <cassert>
#include <iterator>

void KeccakF(uint64_t (&st)[25])
{
    static constexpr uint64_t RNDC[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};
    static constexpr int ROUNDS = 24;

    for (int round = 0; round < ROUNDS; ++round) {
        uint64_t bc0, bc1, bc2, bc3, bc4, t;

        // Theta
        bc0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        bc1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        bc2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        bc3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        bc4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];
        t = bc4 ^ ((bc1 << 1) | (bc1 >> 63));
        st[0] ^= t;
        st[5] ^= t;
        st[10] ^= t;
        st[15] ^= t;
        st[20] ^= t;
        t = bc0 ^ ((bc2 << 1) | (bc2 >> 63));
        st[1] ^= t;
        st[6] ^= t;
        st[11] ^= t;
        st[16] ^= t;
        st[21] ^= t;
        t = bc1 ^ ((bc3 << 1) | (bc3 >> 63));
        st[2] ^= t;
        st[7] ^= t;
        st[12] ^= t;
        st[17] ^= t;
        st[22] ^= t;
        t = bc2 ^ ((bc4 << 1) | (bc4 >> 63));
        st[3] ^= t;
        st[8] ^= t;
        st[13] ^= t;
        st[18] ^= t;
        st[23] ^= t;
        t = bc3 ^ ((bc0 << 1) | (bc0 >> 63));
        st[4] ^= t;
        st[9] ^= t;
        st[14] ^= t;
        st[19] ^= t;
        st[24] ^= t;

        // Rho Pi
        t = st[1];
        bc0 = st[10];
        st[10] = ((t << 1) | (t >> 63));
        t = bc0;
        bc0 = st[7];
        st[7] = ((t << 3) | (t >> 61));
        t = bc0;
        bc0 = st[11];
        st[11] = ((t << 6) | (t >> 58));
        t = bc0;
        bc0 = st[17];
        st[17] = ((t << 10) | (t >> 54));
        t = bc0;
        bc0 = st[18];
        st[18] = ((t << 15) | (t >> 49));
        t = bc0;
        bc0 = st[3];
        st[3] = ((t << 21) | (t >> 43));
        t = bc0;
        bc0 = st[5];
        st[5] = ((t << 28) | (t >> 36));
        t = bc0;
        bc0 = st[16];
        st[16] = ((t << 36) | (t >> 28));
        t = bc0;
        bc0 = st[8];
        st[8] = ((t << 45) | (t >> 19));
        t = bc0;
        bc0 = st[21];
        st[21] = ((t << 55) | (t >> 9));
        t = bc0;
        bc0 = st[24];
        st[24] = ((t << 2) | (t >> 62));
        t = bc0;
        bc0 = st[4];
        st[4] = ((t << 14) | (t >> 50));
        t = bc0;
        bc0 = st[15];
        st[15] = ((t << 27) | (t >> 37));
        t = bc0;
        bc0 = st[23];
        st[23] = ((t << 41) | (t >> 23));
        t = bc0;
        bc0 = st[19];
        st[19] = ((t << 56) | (t >> 8));
        t = bc0;
        bc0 = st[13];
        st[13] = ((t << 8) | (t >> 56));
        t = bc0;
        bc0 = st[12];
        st[12] = ((t << 25) | (t >> 39));
        t = bc0;
        bc0 = st[2];
        st[2] = ((t << 43) | (t >> 21));
        t = bc0;
        bc0 = st[20];
        st[20] = ((t << 62) | (t >> 2));
        t = bc0;
        bc0 = st[14];
        st[14] = ((t << 18) | (t >> 46));
        t = bc0;
        bc0 = st[22];
        st[22] = ((t << 39) | (t >> 25));
        t = bc0;
        bc0 = st[9];
        st[9] = ((t << 61) | (t >> 3));
        t = bc0;
        bc0 = st[6];
        st[6] = ((t << 20) | (t >> 44));
        t = bc0;
        st[1] = ((t << 44) | (t >> 20));

        // Chi Iota
        bc0 = st[0];
        bc1 = st[1];
        bc2 = st[2];
        bc3 = st[3];
        bc4 = st[4];
        st[0] = bc0 ^ (~bc1 & bc2) ^ RNDC[round];
        st[1] = bc1 ^ (~bc2 & bc3);
        st[2] = bc2 ^ (~bc3 & bc4);
        st[3] = bc3 ^ (~bc4 & bc0);
        st[4] = bc4 ^ (~bc0 & bc1);
        bc0 = st[5];
        bc1 = st[6];
        bc2 = st[7];
        bc3 = st[8];
        bc4 = st[9];
        st[5] = bc0 ^ (~bc1 & bc2);
        st[6] = bc1 ^ (~bc2 & bc3);
        st[7] = bc2 ^ (~bc3 & bc4);
        st[8] = bc3 ^ (~bc4 & bc0);
        st[9] = bc4 ^ (~bc0 & bc1);
        bc0 = st[10];
        bc1 = st[11];
        bc2 = st[12];
        bc3 = st[13];
        bc4 = st[14];
        st[10] = bc0 ^ (~bc1 & bc2);
        st[11] = bc1 ^ (~bc2 & bc3);
        st[12] = bc2 ^ (~bc3 & bc4);
        st[13] = bc3 ^ (~bc4 & bc0);
        st[14] = bc4 ^ (~bc0 & bc1);
        bc0 = st[15];
        bc1 = st[16];
        bc2 = st[17];
        bc3 = st[18];
        bc4 = st[19];
        st[15] = bc0 ^ (~bc1 & bc2);
        st[16] = bc1 ^ (~bc2 & bc3);
        st[17] = bc2 ^ (~bc3 & bc4);
        st[18] = bc3 ^ (~bc4 & bc0);
        st[19] = bc4 ^ (~bc0 & bc1);
        bc0 = st[20];
        bc1 = st[21];
        bc2 = st[22];
        bc3 = st[23];
        bc4 = st[24];
        st[20] = bc0 ^ (~bc1 & bc2);
        st[21] = bc1 ^ (~bc2 & bc3);
        st[22] = bc2 ^ (~bc3 & bc4);
        st[23] = bc3 ^ (~bc4 & bc0);
        st[24] = bc4 ^ (~bc0 & bc1);
    }
}

SHA3_256& SHA3_256::Write(const unsigned char* data, size_t len)
{
    if (m_bufsize && len >= sizeof(m_buffer) - m_bufsize) {
        // Fill the buffer and process it.
        std::copy(data, data + (sizeof(m_buffer) - m_bufsize), m_buffer + m_bufsize);
        data += (sizeof(m_buffer) - m_bufsize);
        len -= (sizeof(m_buffer) - m_bufsize);
        m_state[m_pos++] ^= ReadLE64(m_buffer);
        m_bufsize = 0;
        if (m_pos == RATE_BUFFERS) {
            KeccakF(m_state);
            m_pos = 0;
        }
    }
    while (len >= sizeof(m_buffer)) {
        // Process chunks directly from the buffer.
        m_state[m_pos++] ^= ReadLE64(data);
        data += 8;
        len -= 8;
        if (m_pos == RATE_BUFFERS) {
            KeccakF(m_state);
            m_pos = 0;
        }
    }
    if (len) {
        // Keep the remainder in the buffer.
        std::copy(data, data + len, m_buffer + m_bufsize);
        m_bufsize += len;
    }
    return *this;
}

SHA3_256& SHA3_256::Finalize(unsigned char output[OUTPUT_SIZE])
{
    std::fill(m_buffer + m_bufsize, m_buffer + sizeof(m_buffer), 0);
    m_buffer[m_bufsize] ^= 0x06;
    m_state[m_pos] ^= ReadLE64(m_buffer);
    m_state[RATE_BUFFERS - 1] ^= 0x8000000000000000;
    KeccakF(m_state);
    for (unsigned i = 0; i < 4; ++i) {
        WriteLE64(output + 8 * i, m_state[i]);
    }
    return *this;
}

SHA3_256& SHA3_256::Reset()
{
    m_bufsize = 0;
    m_pos = 0;
    std::fill(std::begin(m_state), std::end(m_state), 0);
    return *this;
}
