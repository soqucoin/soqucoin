// standalone_shim.cpp — Replaces soqucoind utilities for standalone liblatticebp build
//
// These functions exist in the full soqucoind binary but are not available
// when building liblatticebp as a standalone shared library for FFI.
// This shim provides equivalent implementations using system primitives.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>

// ── Platform-specific CSPRNG ──
#if defined(__APPLE__)
#include <Security/SecRandom.h>
#elif defined(__linux__) || defined(__ANDROID__)
#include <sys/random.h>
#elif defined(_WIN32)
#include <bcrypt.h>
#pragma comment(lib, "bcrypt")
#else
#include <fstream>
#endif

// ── OpenSSL-free HMAC-SHA256 ──
// Minimal standalone SHA-256 + HMAC for HKDF key derivation.
// Based on FIPS 180-4 (SHA-256) and RFC 2104 (HMAC).

namespace {

struct SHA256State {
    uint32_t h[8];
    uint64_t total;
    uint8_t buf[64];
    size_t buflen;
};

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S0(x) (ROR32(x,2)^ROR32(x,13)^ROR32(x,22))
#define S1(x) (ROR32(x,6)^ROR32(x,11)^ROR32(x,25))
#define s0(x) (ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define s1(x) (ROR32(x,17)^ROR32(x,19)^((x)>>10))

static void sha256_transform(SHA256State& st, const uint8_t block[64]) {
    uint32_t W[64], a,b,c,d,e,f,g,h;
    for (int i = 0; i < 16; i++)
        W[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
               ((uint32_t)block[i*4+2]<<8)|block[i*4+3];
    for (int i = 16; i < 64; i++)
        W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];
    a=st.h[0]; b=st.h[1]; c=st.h[2]; d=st.h[3];
    e=st.h[4]; f=st.h[5]; g=st.h[6]; h=st.h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + S1(e) + CH(e,f,g) + K256[i] + W[i];
        uint32_t t2 = S0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st.h[0]+=a; st.h[1]+=b; st.h[2]+=c; st.h[3]+=d;
    st.h[4]+=e; st.h[5]+=f; st.h[6]+=g; st.h[7]+=h;
}

static void sha256_init(SHA256State& st) {
    st.h[0]=0x6a09e667; st.h[1]=0xbb67ae85; st.h[2]=0x3c6ef372; st.h[3]=0xa54ff53a;
    st.h[4]=0x510e527f; st.h[5]=0x9b05688c; st.h[6]=0x1f83d9ab; st.h[7]=0x5be0cd19;
    st.total = 0; st.buflen = 0;
}

static void sha256_update(SHA256State& st, const uint8_t* data, size_t len) {
    while (len > 0) {
        size_t copy = 64 - st.buflen;
        if (copy > len) copy = len;
        memcpy(st.buf + st.buflen, data, copy);
        st.buflen += copy; data += copy; len -= copy; st.total += copy;
        if (st.buflen == 64) { sha256_transform(st, st.buf); st.buflen = 0; }
    }
}

static void sha256_finalize(SHA256State& st, uint8_t out[32]) {
    uint64_t bits = st.total * 8;
    uint8_t pad = 0x80;
    sha256_update(st, &pad, 1);
    pad = 0;
    while (st.buflen != 56) sha256_update(st, &pad, 1);
    uint8_t len_be[8];
    for (int i = 7; i >= 0; i--) { len_be[i] = bits & 0xff; bits >>= 8; }
    sha256_update(st, len_be, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = st.h[i]>>24; out[i*4+1] = st.h[i]>>16;
        out[i*4+2] = st.h[i]>>8;  out[i*4+3] = st.h[i];
    }
}

} // anonymous namespace

// ── Exported symbols matching soqucoind interfaces ──

// CSHA256 (from crypto/sha256.h)
class CSHA256 {
    SHA256State st;
public:
    static constexpr size_t OUTPUT_SIZE = 32;
    CSHA256() { sha256_init(st); }
    CSHA256& Write(const unsigned char* data, size_t len) {
        sha256_update(st, data, len); return *this;
    }
    void Finalize(unsigned char out[32]) { sha256_finalize(st, out); }
    CSHA256& Reset() { sha256_init(st); return *this; }
};

// CHMAC_SHA256 (from crypto/hmac_sha256.h)
class CHMAC_SHA256 {
    CSHA256 inner, outer;
public:
    static constexpr size_t OUTPUT_SIZE = 32;
    CHMAC_SHA256(const unsigned char* key, size_t keylen) {
        unsigned char rkey[64];
        memset(rkey, 0, 64);
        if (keylen > 64) {
            CSHA256 h; h.Write(key, keylen); h.Finalize(rkey);
        } else {
            memcpy(rkey, key, keylen);
        }
        unsigned char ipad[64], opad[64];
        for (int i = 0; i < 64; i++) { ipad[i] = rkey[i]^0x36; opad[i] = rkey[i]^0x5c; }
        inner.Write(ipad, 64);
        outer.Write(opad, 64);
        volatile unsigned char* p = rkey;
        for (size_t i = 0; i < 64; i++) p[i] = 0;
    }
    CHMAC_SHA256& Write(const unsigned char* data, size_t len) {
        inner.Write(data, len); return *this;
    }
    void Finalize(unsigned char out[32]) {
        unsigned char h[32]; inner.Finalize(h);
        outer.Write(h, 32); outer.Finalize(out);
        volatile unsigned char* p = h;
        for (int i = 0; i < 32; i++) p[i] = 0;
    }
};

// memory_cleanse (from support/cleanse.h)
extern "C" void memory_cleanse(void* ptr, size_t len) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) *p++ = 0;
}

// HKDF_SHA256 (RFC 5869) — standalone implementation
// This is the extern "C" function expected by commitment.cpp under LATTICEBP_STANDALONE
extern "C" void HKDF_SHA256(const uint8_t* ikm, size_t ikm_len,
                             const uint8_t* salt, size_t salt_len,
                             const uint8_t* info, size_t info_len,
                             uint8_t* okm, size_t okm_len) {
    // Extract: PRK = HMAC-SHA256(salt, ikm)
    uint8_t prk[32];
    if (salt && salt_len > 0) {
        CHMAC_SHA256 extractor(salt, salt_len);
        extractor.Write(ikm, ikm_len);
        extractor.Finalize(prk);
    } else {
        uint8_t zero_salt[32] = {};
        CHMAC_SHA256 extractor(zero_salt, 32);
        extractor.Write(ikm, ikm_len);
        extractor.Finalize(prk);
    }

    // Expand: OKM = T(1) || T(2) || ... where T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
    uint8_t t[32] = {};
    size_t t_len = 0;
    uint8_t counter = 1;
    size_t pos = 0;

    while (pos < okm_len) {
        CHMAC_SHA256 expander(prk, 32);
        if (t_len > 0) expander.Write(t, t_len);
        if (info && info_len > 0) expander.Write(info, info_len);
        expander.Write(&counter, 1);
        expander.Finalize(t);
        t_len = 32;

        size_t copy = okm_len - pos;
        if (copy > 32) copy = 32;
        memcpy(okm + pos, t, copy);
        pos += copy;
        counter++;
    }

    volatile unsigned char* p = prk;
    for (int i = 0; i < 32; i++) p[i] = 0;
}

// GetStrongRandBytes (from random.h) — CSPRNG
extern "C" void GetStrongRandBytes(unsigned char* out, int num) {
#if defined(__APPLE__)
    (void)SecRandomCopyBytes(kSecRandomDefault, num, out);
#elif defined(__ANDROID__)
    // Android: /dev/urandom always available, getrandom() needs API 28+
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) { fread(out, 1, num, f); fclose(f); }
#elif defined(__linux__)
    getrandom(out, num, 0);
#elif defined(_WIN32)
    BCryptGenRandom(NULL, out, num, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    std::ifstream f("/dev/urandom", std::ios::binary);
    f.read((char*)out, num);
#endif
}
