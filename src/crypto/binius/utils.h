#pragma once

#include <cstdint>
#include <cstring>
#include <type_traits>
#include <vector>

#if defined(__GNUC__) || defined(__clang__)
#define FORCE_INLINE __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
#define FORCE_INLINE __forceinline
#else
#define FORCE_INLINE inline
#endif

namespace binius
{

// Portable bit manipulation helpers
struct Utils {
    static FORCE_INLINE uint64_t Pmul64(uint64_t a, uint64_t b)
    {
        uint64_t res = 0;
        for (int i = 0; i < 64; ++i) {
            if ((b >> i) & 1) {
                res ^= (a << i);
            }
        }
        return res;
    }

    // Carry-less multiplication of two 64-bit integers into a 128-bit integer
    static FORCE_INLINE unsigned __int128 Pmul64to128(uint64_t a, uint64_t b)
    {
#ifdef __PCLMUL__
        // TODO: Add PCLMULQDQ intrinsic support if available and enabled
        // For now, use portable fallback for broad compatibility
#endif
        unsigned __int128 res = 0;
        for (int i = 0; i < 64; ++i) {
            if ((b >> i) & 1) {
                res ^= ((unsigned __int128)a << i);
            }
        }
        return res;
    }

    static FORCE_INLINE uint64_t ReverseBits64(uint64_t x)
    {
        x = ((x & 0x5555555555555555ULL) << 1) | ((x & 0xAAAAAAAAAAAAAAAAULL) >> 1);
        x = ((x & 0x3333333333333333ULL) << 2) | ((x & 0xCCCCCCCCCCCCCCCCULL) >> 2);
        x = ((x & 0x0F0F0F0F0F0F0F0FULL) << 4) | ((x & 0xF0F0F0F0F0F0F0F0ULL) >> 4);
        x = ((x & 0x00FF00FF00FF00FFULL) << 8) | ((x & 0xFF00FF00FF00FF00ULL) >> 8);
        x = ((x & 0x0000FFFF0000FFFFULL) << 16) | ((x & 0xFFFF0000FFFF0000ULL) >> 16);
        return (x << 32) | (x >> 32);
    }
};

} // namespace binius
