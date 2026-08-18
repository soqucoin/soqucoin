#ifndef LAZER_CONFIGOPTS_H
#define LAZER_CONFIGOPTS_H

#define TARGET_GENERIC 0
#define TARGET_AMD64 1

#define RNG_SHAKE128 0
#define RNG_AES256CTR 1

#define ASSERT_DISABLED 0
#define ASSERT_ENABLED 1

#define TIMERS_DISABLED 0
#define TIMERS_ENABLED 1

#define DEBUGINFO_DISABLED 0
#define DEBUGINFO_ENABLED 1

#define VALGRIND_DISABLED 0
#define VALGRIND_ENABLED 1

#endif

#ifndef LAZER_CONFIG_H
#define LAZER_CONFIG_H

/*
 * TARGET: GENERIC, AMD64
 * Architecture target.
 */
#define TARGET TARGET_AMD64

/*
 * RNG: SHAKE128, AES256CTR
 * Use Shake128 or AES-256-CTR for pseudorandom generation.
 */
#define RNG RNG_AES256CTR

/*
 * ASSERT: ENABLED, DISABLED
 * Enable or diasble assertions.
 */
#define ASSERT ASSERT_DISABLED

/*
 * TIMERS: ENABLED, DISABLED
 * Run timers and print the results.
 */
#define TIMERS TIMERS_DISABLED

/*
 * DEBUGINFO: ENABLED, DISABLED
 * Print out debug information.
 */
#define DEBUGINFO DEBUGINFO_DISABLED

/*
 * VALGRIND: ENABLED, DISABLED
 * Build and run valgrind tests.
 * Requires valgrind installation.
 * Requires ASSERT_DISABLED
 */
#define VALGRIND VALGRIND_DISABLED

#endif

#ifndef LAZER_H
#define LAZER_H

/**
 * \file   lazer.h
 * \brief  lazer's C interface.
 */

/* update on release. XXX */
#define LAZER_VERSION_MAJOR 0
#define LAZER_VERSION_MINOR 1
#define LAZER_VERSION_PATCH 0
#define LAZER_VERSION "0.1.0"

#if DEBUGINFO == DEBUGINFO_ENABLED
struct debuginfo
{
  int level;
  int print_function_entry;
  int print_function_return;
  int print_tocrt;
  int print_fromcrt;
  int print_rej;
};
extern struct debuginfo debug;

#define DEBUG_LEVEL debug.level
#define DEBUG_LEVEL_SET(_lvl_) debug.level = (_lvl_)
#define DEBUG_PRINT_REJ debug.print_rej
#define DEBUG_PRINT_REJ_START() debug.print_rej = 1
#define DEBUG_PRINT_REJ_STOP() debug.print_rej = 0
#define DEBUG_PRINT_TOCRT debug.print_tocrt
#define DEBUG_PRINT_TOCRT_START() debug.print_tocrt = 1
#define DEBUG_PRINT_TOCRT_STOP() debug.print_tocrt = 0
#define DEBUG_PRINT_FROMCRT debug.print_fromcrt
#define DEBUG_PRINT_FROMCRT_START() debug.print_fromcrt = 1
#define DEBUG_PRINT_FROMCRT_STOP() debug.print_fromcrt = 0
#define DEBUG_PRINT_FUNCTION_ENTRY debug.print_function_entry
#define DEBUG_PRINT_FUNCTION_ENTRY_START() debug.print_function_entry = 1
#define DEBUG_PRINT_FUNCTION_ENTRY_STOP() debug.print_function_entry = 0
#define DEBUG_PRINT_FUNCTION_RETURN debug.print_function_return
#define DEBUG_PRINT_FUNCTION_RETURN_START() debug.print_function_return = 1
#define DEBUG_PRINT_FUNCTION_RETURN_STOP() debug.print_function_return = 0

#define DEBUG_PRINTF(cnd, fmt, ...)                                           \
  do                                                                          \
    {                                                                         \
      if (cnd)                                                                \
        printf ("DEBUG: " fmt "\n", __VA_ARGS__);                             \
    }                                                                         \
  while (0)
#else
#define DEBUG_LEVEL (void)0
#define DEBUG_LEVEL_SET(_lvl_) (void)(0)
#define DEBUG_PRINT_REJ (void)0
#define DEBUG_PRINT_REJ_START() (void)0
#define DEBUG_PRINT_REJ_STOP() (void)0
#define DEBUG_PRINT_TOCRT (void)0
#define DEBUG_PRINT_TOCRT_START() (void)0
#define DEBUG_PRINT_TOCRT_STOP() (void)0
#define DEBUG_PRINT_FROMCRT (void)0
#define DEBUG_PRINT_FROMCRT_START() (void)0
#define DEBUG_PRINT_FROMCRT_STOP() (void)0
#define DEBUG_PRINT_FUNCTION_ENTRY (void)0
#define DEBUG_PRINT_FUNCTION_ENTRY_START() (void)0
#define DEBUG_PRINT_FUNCTION_ENTRY_STOP() (void)0
#define DEBUG_PRINT_FUNCTION_RETURN (void)0
#define DEBUG_PRINT_FUNCTION_RETURN_START() (void)0
#define DEBUG_PRINT_FUNCTION_RETURN_STOP() (void)0
#define DEBUG_PRINTF(fmt, ...) (void)0
#endif

/********************************************************************
 * 1 Headers and defines
 */

#if __linux__

#define _OS_LINUX
#include <endian.h>

#elif __APPLE__

#include <TargetConditionals.h>

#if TARGET_OS_IPHONE

#define _OS_IOS
#include <libkern/OSByteOrder.h>
#include <machine/endian.h>
#include <strings.h>

#define explicit_bzero bzero

#define htobe16(x) OSSwapHostToBigInt16 (x)
#define htole16(x) OSSwapHostToLittleInt16 (x)
#define be16toh(x) OSSwapBigToHostInt16 (x)
#define le16toh(x) OSSwapLittleToHostInt16 (x)
#define htobe32(x) OSSwapHostToBigInt32 (x)
#define htole32(x) OSSwapHostToLittleInt32 (x)
#define be32toh(x) OSSwapBigToHostInt32 (x)
#define le32toh(x) OSSwapLittleToHostInt32 (x)
#define htobe64(x) OSSwapHostToBigInt64 (x)
#define htole64(x) OSSwapHostToLittleInt64 (x)
#define be64toh(x) OSSwapBigToHostInt64 (x)
#define le64toh(x) OSSwapLittleToHostInt64 (x)

#elif TARGET_OS_MAC

#define _OS_MACOS
#include <libkern/OSByteOrder.h>
#include <machine/endian.h>
#include <strings.h>
#include <sys/random.h>

#define explicit_bzero bzero

#define htobe16(x) OSSwapHostToBigInt16 (x)
#define htole16(x) OSSwapHostToLittleInt16 (x)
#define be16toh(x) OSSwapBigToHostInt16 (x)
#define le16toh(x) OSSwapLittleToHostInt16 (x)
#define htobe32(x) OSSwapHostToBigInt32 (x)
#define htole32(x) OSSwapHostToLittleInt32 (x)
#define be32toh(x) OSSwapBigToHostInt32 (x)
#define le32toh(x) OSSwapLittleToHostInt32 (x)
#define htobe64(x) OSSwapHostToBigInt64 (x)
#define htole64(x) OSSwapHostToLittleInt64 (x)
#define be64toh(x) OSSwapBigToHostInt64 (x)
#define le64toh(x) OSSwapLittleToHostInt64 (x)

#endif

#else
#error "Unsupported platform"
#endif

#include <sys/cdefs.h> /* for __BEGIN_DECLS, __END_DECLS */

#include <stddef.h> /* for FILE */
#include <stdint.h> /* for exact-width int types */
#include <stdio.h>  /* for size_t */
#include <stdlib.h>
#include <string.h>

#if TARGET == TARGET_AMD64
#include <immintrin.h>
#include <x86intrin.h>
#endif

#include <gmp.h>

__BEGIN_DECLS

#define _ALIGN8 __attribute__ ((aligned (8)))
#define _ALIGN16 __attribute__ ((aligned (16)))
#define _ALIGN32 __attribute__ ((aligned (32)))
#define _ALIGN64 __attribute__ ((aligned (64)))

#define LIKELY(expr) __builtin_expect ((expr) != 0, 1)
#define UNLIKELY(expr) __builtin_expect ((expr) != 0, 0)
#define UNUSED __attribute__ ((unused))

#define BSWAP64(a) __builtin_bswap64 (a)
#define BSWAP(a) __builtin_bswap (a)

/* XXX allow 2^LOG2NADDS_CRTREP adds/subs in crt representation of polys */
#define LOG2NADDS_CRTREP 8

/* flags */
#define FZERO 1 /* object is zero */

/********************************************************************
 * 2 API types
 */

typedef struct
{
  uint64_t s[25];
  unsigned int pos;
  int final;
} shake128_state_struct;
typedef shake128_state_struct shake128_state_t[1];
typedef shake128_state_struct *shake128_state_ptr;
typedef const shake128_state_struct *shake128_state_srcptr;

typedef struct
{
#if TARGET == TARGET_GENERIC
  uint8_t expanded[4][60];
  uint8_t nonce[16];
  uint8_t cache[16];
  uint8_t *cache_ptr;
  unsigned int nbytes;
#elif TARGET == TARGET_AMD64
  __m128i rkeys[16];
  _ALIGN16 uint8_t n2[16];
  _ALIGN16 uint8_t cache[8 * 16]; /* LOOP (8) */
  uint8_t *cache_ptr;
  unsigned int nbytes;
#else
#error "Invalid target option."
#endif
} aes256ctr_state_struct;
typedef aes256ctr_state_struct aes256ctr_state_t[1];
typedef aes256ctr_state_struct *aes256ctr_state_ptr;
typedef const aes256ctr_state_struct *aes256ctr_state_srcptr;

typedef struct
{
#if RNG == RNG_SHAKE128
  shake128_state_t state;
#elif RNG == RNG_AES256CTR
  aes256ctr_state_t state;
#else
#error "Invalid rng option."
#endif
} rng_state_struct;
typedef rng_state_struct rng_state_t[1];
typedef rng_state_struct *rng_state_ptr;
typedef const rng_state_struct *rng_state_srcptr;

typedef uint64_t limb_t; /* XXX must match mp_limbt_t */
typedef int64_t crtcoeff_t;
#define CRTCOEFF_NBITS 64
#define CRTCOEFF_MAX INT64_MAX
typedef __int128 crtcoeff_dbl_t;

/*
 * 2^NBITS_LIMB bit signed integer
 */
typedef struct
{
  limb_t *limbs;
  unsigned int nlimbs;
  limb_t neg;
} int_struct;
typedef int_struct int_t[1];
typedef int_struct *int_ptr;
typedef const int_struct *int_srcptr;

/*
 * ECRT [1]:
 *
 * i in [0,s-1]
 *
 * precomputation:
 * P = prod(p[i]) product of moduli >= p[s-1]
 * Pp[i] = P/p[i]
 * k[i] * P/p[i] = 1 (mod p[i]), chose k[i] in [-(p[i]-1)/2,(p[i]-1)/2]
 *
 * computation:
 * x[i] = k[i] * u (mod p[i]), chose x[i] in [-(p[i]-1)/2,(p[i]-1)/2]
 * z = sum(x[i]/p[i])
 *
 * u = P * z - P * round(z) = sum(P/p[i] * x[i]) - P * round(z)
 *   = sum(Pp[i] * x[i]) - P * round(z)
 *
 * [1] https://cr.yp.to/papers.html#mmecrt
 */
typedef struct
{
  /* this modulus */
  const crtcoeff_t *roots;     /* in mont domain */
  const crtcoeff_t p;          /* modulus < 50 bit */
  const crtcoeff_t mont_pinv;  /* 1/p mod 2^32 */
  const crtcoeff_t mont_redr;  /* (2^32)^2 mod p, XXX needed ? == roots[0] */
  const crtcoeff_t intt_const; /* 1 / deg mod p */
  const crtcoeff_t m;          /* inverse of product of moduli > p mod p */
  /* product of moduli >= p */
  const int_srcptr P;
  const int_srcptr *Pp;
  const crtcoeff_t *k;
  const unsigned int nbits; /* bit-length */
} modulus_struct;
typedef modulus_struct modulus_t[1];
typedef modulus_struct *modulus_ptr;
typedef const modulus_struct *modulus_srcptr;

#include "src/moduli.h"

typedef struct
{
  /* allocated space (limbs||int structs)*/
  void *bytes;
  size_t nbytes;

  int_ptr elems;
  unsigned int nlimbs;
  unsigned int nelems;
  unsigned int stride_elems;
} intvec_struct;
typedef intvec_struct intvec_t[1];
typedef intvec_struct *intvec_ptr;
typedef const intvec_struct *intvec_srcptr;

typedef struct
{
  /* allocated space (limbs||ints structs)*/
  void *bytes;
  size_t nbytes;

  unsigned int cpr; /* cols per row */

  int_ptr elems;
  unsigned int nlimbs;

  unsigned int ncols;
  unsigned int stride_col;

  unsigned int nrows;
  unsigned int stride_row;
} intmat_struct;
typedef intmat_struct intmat_t[1];
typedef intmat_struct *intmat_ptr;
typedef const intmat_struct *intmat_srcptr;

typedef struct
{
  const int_srcptr q;       /* modulus */
  const unsigned int d;     /* degree */
  const unsigned int log2q; /* ceil(log(q-1)) bits represent int mod q */
  const unsigned int log2d; /* log(d) */

  const modulus_srcptr *moduli; /* crt moduli */
  const unsigned int nmoduli;   /* number of crt moduli */
  const int_srcptr Pmodq;
  const int_srcptr *Ppmodq;

  const int_srcptr inv2; /* 2^-1 mod q */
} polyring_struct;
typedef polyring_struct polyring_t[1];
typedef polyring_struct *polyring_ptr;
typedef const polyring_struct *polyring_srcptr;

typedef struct
{
  polyring_srcptr ring;

  intvec_ptr coeffs;
  crtcoeff_t *crtrep;

  void *mem;
  int crt;
  uint32_t flags;
} poly_struct;
typedef poly_struct poly_t[1];
typedef poly_struct *poly_ptr;
typedef const poly_struct *poly_srcptr;

typedef struct
{
  polyring_srcptr ring;

  poly_ptr elems;
  unsigned int nelems;
  unsigned int stride_elems;

  void *mem;
  uint32_t flags;
} polyvec_struct;
typedef polyvec_struct polyvec_t[1];
typedef polyvec_struct *polyvec_ptr;
typedef const polyvec_struct *polyvec_srcptr;

typedef struct
{
  polyring_srcptr ring;

  unsigned int cpr; /* cols per row */

  poly_ptr elems;

  unsigned int ncols;
  unsigned int stride_col;

  unsigned int nrows;
  unsigned int stride_row;

  void *mem;
  uint32_t flags;
} polymat_struct;
typedef polymat_struct polymat_t[1];
typedef polymat_struct *polymat_ptr;
typedef const polymat_struct *polymat_srcptr;

typedef struct
{
  poly_ptr poly;
  uint16_t elem;
} _spolyvec_struct;
typedef _spolyvec_struct _spolyvec_t[1];
typedef _spolyvec_struct *_spolyvec_ptr;
typedef const _spolyvec_struct *_spolyvec_srcptr;

typedef struct
{
  polyring_srcptr ring;
  unsigned int nelems_max;

  unsigned int nelems;
  _spolyvec_ptr elems;

  int sorted;
} spolyvec_struct;
typedef spolyvec_struct spolyvec_t[1];
typedef spolyvec_struct *spolyvec_ptr;
typedef const spolyvec_struct *spolyvec_srcptr;

typedef struct
{
  poly_ptr poly;
  uint16_t row;
  uint16_t col;
} _spolymat_struct;
typedef _spolymat_struct _spolymat_t[1];
typedef _spolymat_struct *_spolymat_ptr;
typedef const _spolymat_struct *_spolymat_srcptr;

typedef struct
{
  polyring_srcptr ring;
  unsigned int nrows;
  unsigned int ncols;
  unsigned int nelems_max;

  unsigned int nelems;
  _spolymat_ptr elems;

  int sorted;
} spolymat_struct;
typedef spolymat_struct spolymat_t[1];
typedef spolymat_struct *spolymat_ptr;
typedef const spolymat_struct *spolymat_srcptr;

typedef struct
{
  const uint8_t *in;
  uint8_t *out;
  unsigned int byte_off;
  unsigned int bit_off;
} coder_state_struct;
typedef coder_state_struct coder_state_t[1];
typedef coder_state_struct *coder_state_ptr;
typedef const coder_state_struct *coder_state_srcptr;

typedef struct
{
  const int_srcptr q;
  const int_srcptr qminus1;
  const int_srcptr m;
  const int_srcptr mby2;
  const int_srcptr gamma;
  const int_srcptr gammaby2;
  const int_srcptr pow2D;
  const int_srcptr pow2Dby2;
  const unsigned int D;
  const int m_odd;
  const unsigned int log2m;
} dcompress_params_struct;
typedef dcompress_params_struct dcompress_params_t[1];
typedef dcompress_params_struct *dcompress_params_ptr;
typedef const dcompress_params_struct *dcompress_params_srcptr;

typedef struct
{
  const polyring_srcptr ring;
  const dcompress_params_srcptr dcompress;
  /* dimensions  */
  const unsigned int m1;   /* length of "short" message s1 */
  const unsigned int m2;   /* length of randomness s2 */
  const unsigned int l;    /* length of "large" message m */
  const unsigned int lext; /* length of extension of m */
  const unsigned int kmsis;
  /* norms */
  const int_srcptr Bsqr; /* floor (B^2) */
  const int64_t nu;      /* s2 uniform in [-nu,nu]*/
  const int64_t omega;   /* challenges uniform in [-omega,omega], o(c)=c */
  const unsigned int log2omega;
  const uint64_t eta; /* sqrt(l1(o(c)*c)) <= eta XXX sqrt? */
  /* rejection sampling */
  const int rej1;                /* do rejection sampling on s1 */
  const unsigned int log2stdev1; /* stdev1 = 1.55 * 2^log2stdev1 */
  const int_srcptr scM1;         /* scaled M1: round(M1 * 2^128) */
  const int_srcptr stdev1sqr;
  const int rej2;                /* do rejection sampling on s2 */
  const unsigned int log2stdev2; /* stdev2 = 1.55 * 2^log2stdev2 */
  const int_srcptr scM2;         /* scaled M2: round(M2 * 2^128) */
  const int_srcptr stdev2sqr;
} abdlop_params_struct;
typedef abdlop_params_struct abdlop_params_t[1];
typedef abdlop_params_struct *abdlop_params_ptr;
typedef const abdlop_params_struct *abdlop_params_srcptr;

typedef struct
{
  const abdlop_params_srcptr quad_eval;
  const abdlop_params_srcptr quad_many;
  const unsigned int lambda;

} lnp_quad_eval_params_struct;
typedef lnp_quad_eval_params_struct lnp_quad_eval_params_t[1];
typedef lnp_quad_eval_params_struct *lnp_quad_eval_params_ptr;
typedef const lnp_quad_eval_params_struct *lnp_quad_eval_params_srcptr;

typedef struct
{
  abdlop_params_srcptr tbox;
  lnp_quad_eval_params_srcptr quad_eval;

  /* dimensions */
  const unsigned int nbin;
  const unsigned int *const n;
  const unsigned int nprime;
  const unsigned int Z;
  const unsigned int nex;

  /* rejection sampling */
  const int rej3;                /* do rejection sampling on s3 */
  const unsigned int log2stdev3; /* stdev3 = 1.55 * 2^log2stdev1 */
  const int_srcptr scM3;         /* scaled M3: round(M3 * 2^128) */
  const int_srcptr stdev3sqr;
  const int rej4;                /* do rejection sampling on s4 */
  const unsigned int log2stdev4; /* stdev4 = 1.55 * 2^log2stdev2 */
  const int_srcptr scM4;         /* scaled M4: round(M4 * 2^128) */
  const int_srcptr stdev4sqr;

  /* bounds */
  const int_srcptr Bz3sqr;
  const int_srcptr Bz4;
  const int_srcptr *l2Bsqr; /* squared euclidean norm bounds */

  const int_srcptr inv4;

  /* expected proof size in bytes */
  const unsigned long prooflen;
} lnp_tbox_params_struct;
typedef lnp_tbox_params_struct lnp_tbox_params_t[1];
typedef lnp_tbox_params_struct *lnp_tbox_params_ptr;
typedef const lnp_tbox_params_struct *lnp_tbox_params_srcptr;

typedef struct
{
  /* params */
  lnp_tbox_params_srcptr params;
  /* public params */
  uint8_t ppseed[32];
  polymat_t A1;
  polymat_t A2prime;
  polymat_t Bprime;
  /* commitment */
  polyvec_t tA1;
  polyvec_t tA2;
  polyvec_t tB;
  /* proof */
  polyvec_t h;
  polyvec_t hint;
  polyvec_t z1;
  polyvec_t z21;
  polyvec_t z3;
  polyvec_t z4;
  poly_t c;
  /* statement */
  spolymat_ptr *R2;
  spolyvec_ptr *r1;
  poly_ptr *r0;
  unsigned int N;
  spolymat_ptr *R2prime;
  spolyvec_ptr *r1prime;
  poly_ptr *r0prime;
  unsigned int M;
  polymat_ptr *Es, *Em;
  polyvec_ptr *v;
  polymat_ptr Ps, Pm;
  polyvec_ptr f;
  polymat_ptr Ds, Dm;
  polyvec_ptr u;
  /* hashes of (sub)statements */
  uint8_t hash_quadeqs[32];
  uint8_t hash_evaleqs[32];
  uint8_t hash_l2[32];
  uint8_t hash_bin[32];
  uint8_t hash_arp[32];
  /* init */
  int statement_l2_set;
  int statement_bin_set;
  int statement_arp_set;
} _lnp_state_struct;
typedef _lnp_state_struct _lnp_state_t[1];
typedef _lnp_state_struct *_lnp_state_ptr;
typedef const _lnp_state_struct *_lnp_state_srcptr;

typedef struct
{
  /* public */
  _lnp_state_t state;
  /* secret */
  polyvec_t s1;
  polyvec_t s2;
  polyvec_t m;
  int witness_set;
} lnp_prover_state_struct;
typedef lnp_prover_state_struct lnp_prover_state_t[1];
typedef lnp_prover_state_struct *lnp_prover_state_ptr;
typedef const lnp_prover_state_struct *lnp_prover_state_srcptr;

typedef struct
{
  _lnp_state_t state;
} lnp_verifier_state_struct;
typedef lnp_verifier_state_struct lnp_verifier_state_t[1];
typedef lnp_verifier_state_struct *lnp_verifier_state_ptr;
typedef const lnp_verifier_state_struct *lnp_verifier_state_srcptr;

typedef struct
{
  lnp_tbox_params_srcptr tbox_params;
  const unsigned int dprime;
  int_srcptr p;
  int_srcptr pinv;
  const unsigned int k;

  const unsigned int *const s1_indices;
  const unsigned int ns1_indices;
  const unsigned int *const m_indices;
  const unsigned int nm_indices;

  const unsigned int *const Ps;
  const unsigned int Ps_nrows;

  const unsigned int *const *const Es;
  const unsigned int *Es_nrows;

  const unsigned int *const *const Em;
  const unsigned int *Em_nrows;
} lin_params_struct;
typedef lin_params_struct lin_params_t[1];
typedef lin_params_struct *lin_params_ptr;
typedef const lin_params_struct *lin_params_srcptr;

typedef struct
{
  lin_params_srcptr params;

  polymat_ptr Ds;
  polymat_ptr Dm;
  polyvec_ptr u;
} _lin_state_struct;
typedef _lin_state_struct _lin_state_t[1];
typedef _lin_state_struct *_lin_state_ptr;
typedef const _lin_state_struct *_lin_state_srcptr;

typedef struct
{
  /* params */
  lnp_tbox_params_srcptr params;
  /* public params */
  uint8_t ppseed[32];
  polymat_t A1;
  polymat_t A2prime;
  polymat_t Bprime;
  /* commitment */
  polyvec_t tA1;
  polyvec_t tA2;
  polyvec_t tB;
  /* proof */
  polyvec_t h;
  polyvec_t hint;
  polyvec_t z1;
  polyvec_t z21;
  polyvec_t z3;
  polyvec_t z4;
  poly_t c;
  /* statement */
  polymat_ptr Ds, Dm;
  polyvec_ptr u;
  /* hashes of (sub)statements */
  uint8_t hash_arp[32];
  /* init */
  int statement_l2_set;
  int statement_bin_set;
  int statement_arp_set;
} __lnp_state_struct;
typedef __lnp_state_struct __lnp_state_t[1];
typedef __lnp_state_struct *__lnp_state_ptr;
typedef const __lnp_state_struct *__lnp_state_srcptr;

typedef struct
{
  /* public */
  __lnp_state_t state;
  /* secret */
  polyvec_t s1;
  polyvec_t s2;
  polyvec_t m;
  int witness_set;
} _lnp_prover_state_struct;
typedef _lnp_prover_state_struct _lnp_prover_state_t[1];
typedef _lnp_prover_state_struct *_lnp_prover_state_ptr;
typedef const _lnp_prover_state_struct *_lnp_prover_state_srcptr;

typedef struct
{
  __lnp_state_t state;
} _lnp_verifier_state_struct;
typedef _lnp_verifier_state_struct _lnp_verifier_state_t[1];
typedef _lnp_verifier_state_struct *_lnp_verifier_state_ptr;
typedef const _lnp_verifier_state_struct *_lnp_verifier_state_srcptr;

typedef struct
{
  _lnp_prover_state_t lnp_state;
  _lin_state_t state;
} lin_prover_state_struct;
typedef lin_prover_state_struct lin_prover_state_t[1];
typedef lin_prover_state_struct *lin_prover_state_ptr;
typedef const lin_prover_state_struct *lin_prover_state_srcptr;

typedef struct
{
  _lnp_verifier_state_t lnp_state;
  _lin_state_t state;
} lin_verifier_state_struct;
typedef lin_verifier_state_struct lin_verifier_state_t[1];
typedef lin_verifier_state_struct *lin_verifier_state_ptr;
typedef const lin_verifier_state_struct *lin_verifier_state_srcptr;

typedef struct
{
  /* secret */
  uint8_t privkey[1281];
  /* public */
  int16_t pubkey[512];
  int16_t Ar1[512];
  int16_t Ar2[512];
  int16_t Am[512];
  int16_t Atau[512];

  lin_verifier_state_t p1;
} signer_state_struct;
typedef signer_state_struct signer_state_t[1];
typedef signer_state_struct *signer_state_ptr;
typedef const signer_state_struct *signer_state_srcptr;

typedef struct
{
  int16_t pubkey[512];
  int16_t Ar1[512];
  int16_t Ar2[512];
  int16_t Am[512];
  int16_t Atau[512];

  lin_verifier_state_t p2;
} verifier_state_struct;
typedef verifier_state_struct verifier_state_t[1];
typedef verifier_state_struct *verifier_state_ptr;
typedef const verifier_state_struct *verifier_state_srcptr;

typedef struct
{
  /* secret */
  uint8_t m[512 / 8];
  int16_t r1[512];
  int16_t r2[512];
  /* public */
  int16_t pubkey[512];
  int16_t Ar1[512];
  int16_t Ar2[512];
  int16_t Am[512];
  int16_t Atau[512];

  lin_prover_state_t p1;
  lin_prover_state_t p2;
} user_state_struct;
typedef user_state_struct user_state_t[1];
typedef user_state_struct *user_state_ptr;
typedef const user_state_struct *user_state_srcptr;

/* forward declarations of internal stuff */
void *hexl_ntt_alloc (uint64_t d, uint64_t p);
void hexl_ntt_fwd (void *ntt, int64_t *out, uint64_t out_mod_factor,
                   const int64_t *in, uint64_t in_mod_factor);
void hexl_ntt_inv (void *ntt, int64_t *out, uint64_t out_mod_factor,
                   const int64_t *in, uint64_t in_mod_factor);
void hexl_ntt_free (void *ntt);

void hexl_ntt_add (int64_t *r, const int64_t *a, const int64_t *b, uint64_t d,
                   uint64_t p);
void hexl_ntt_sub (int64_t *r, const int64_t *a, const int64_t *b, uint64_t d,
                   uint64_t p);
void hexl_ntt_mul (int64_t *r, const int64_t *a, const int64_t *b,
                   uint64_t in_mod_factor, uint64_t d, uint64_t p);
void hexl_ntt_scale (int64_t *r, const uint64_t s, const int64_t *b, int64_t d,
                     uint64_t p, uint64_t in_mod_factor);
void hexl_ntt_red (int64_t *r, uint64_t out_mod_factor, const int64_t *a,
                   uint64_t in_mod_factor, uint64_t d, uint64_t p);

/********************************************************************
 * 3.1 API functions and macros
 */

// __attribute__ ((constructor))  // XXX does not work with hexl init
void lazer_init (void);

unsigned int lazer_get_version_major (void);
unsigned int lazer_get_version_minor (void);
unsigned int lazer_get_version_patch (void);
const char *lazer_get_version (void);

void lazer_set_memory_functions (void *(*nalloc) (size_t),
                                 void *(*nrealloc) (void *, size_t, size_t),
                                 void (*nfree) (void *, size_t));
void lazer_get_memory_functions (void *(**nalloc) (size_t),
                                 void *(**nrealloc) (void *, size_t, size_t),
                                 void (**nfree) (void *, size_t));

void bytes_urandom (uint8_t *bytes, const size_t len);
void bytes_clear (uint8_t *bytes, const size_t len);
size_t bytes_out_str (FILE *stream, const uint8_t *bytes, size_t len);
size_t bytes_inp_str (uint8_t *bytes, size_t len, FILE *stream);
size_t bytes_out_raw (FILE *stream, const uint8_t *bytes, size_t len);
size_t bytes_inp_raw (uint8_t *bytes, size_t len, FILE *stream);

void shake128_init (shake128_state_t state);
void shake128_absorb (shake128_state_t state, const uint8_t *in, size_t len);
void shake128_squeeze (shake128_state_t state, uint8_t *out, size_t len);
void shake128_clear (shake128_state_t state);

void rng_init (rng_state_t state, const uint8_t seed[32], uint64_t dom);
void rng_urandom (rng_state_t state, uint8_t *out, size_t outlen);
void rng_clear (rng_state_t state);

#define INT_T(__name__, __nlimbs__)                                           \
  _ALIGN8 uint8_t __name__##bytes__[_sizeof_int_data (__nlimbs__)];           \
  int_t __name__;                                                             \
  _int_init (__name__, __nlimbs__, __name__##bytes__);

void int_alloc (int_ptr r, unsigned int nlimbs);
void int_free (int_ptr r);
static inline void int_set_zero (int_t r);
static inline void int_set_one (int_t r);
static inline unsigned int int_get_nlimbs (const int_t a);
static inline void int_set (int_t r, const int_t a);
static inline void int_set_zero (int_t r);
static inline void int_set_one (int_t r);
static inline void int_set_i64 (int_t r, int64_t a);
static inline int64_t int_get_i64 (const int_t r);
static inline int int_sgn (const int_t a);
static inline void int_neg (int_t r, const int_t a);
static inline void int_mul_sgn_self (int_t r, int sgn);
static inline void int_neg_self (int_t r);
static inline void int_abs (int_t r, const int_t a);
static inline int int_eqzero (const int_t a);
static inline int int_eq (const int_t a, const int_t b);
static inline int int_lt (const int_t a, const int_t b);
static inline int int_le (const int_t a, const int_t b);
static inline int int_gt (const int_t a, const int_t b);
static inline int int_ge (const int_t a, const int_t b);
static inline int int_abseq (const int_t a, const int_t b);
static inline int int_abslt (const int_t a, const int_t b);
static inline int int_absle (const int_t a, const int_t b);
static inline int int_absgt (const int_t a, const int_t b);
static inline int int_absge (const int_t a, const int_t b);
static inline void int_rshift (int_t r, const int_t a, unsigned int n);
static inline void int_lshift (int_t r, const int_t a, unsigned int n);
static inline void int_add (int_t r, const int_t a, const int_t b);
static inline void int_add_ct (int_t r, const int_t a, const int_t b); // XXX
static inline void int_sub (int_t r, const int_t a, const int_t b);
static inline void int_sub_ct (int_t r, const int_t a, const int_t b); // XXX
static inline void int_redc (int_t r, const int_t a, const int_t m);
static inline void int_redc_ct (int_t r, const int_t a, const int_t m);
void int_mul (int_t r, const int_t a, const int_t b);
void int_sqr (int_t r, const int_t a);
void int_addmul (int_t r, const int_t a, const int_t b);
void int_submul (int_t r, const int_t a, const int_t b);
void int_addsqr (int_t r, const int_t a);
void int_subsqr (int_t r, const int_t a);
void int_div (int_t rq, int_t rr, const int_t a, const int_t b);
void int_mod (int_t r, const int_t a, const int_t m);
void int_invmod (int_t r, const int_t a, const int_t m);
void int_redc (int_t r, const int_t a, const int_t m);
void int_redp (int_t r, const int_t a, const int_t m);
void int_brandom (int_t r, unsigned int k, const uint8_t seed[32],
                  uint32_t dom);
void int_grandom (int_t r, unsigned int log2o, const uint8_t seed[32],
                  uint32_t dom);
void int_urandom (int_t r, const int_t mod, unsigned int log2mod,
                  const uint8_t seed[32], uint32_t dom);
void int_urandom_bnd (int_t r, const int_t lo, const int_t hi,
                      const uint8_t seed[32], uint32_t dom);
void int_binexp (poly_t upsilon, poly_t powB, int_srcptr B);
size_t int_out_str (FILE *stream, int base, const int_t a);
size_t int_inp_str (int_t r, FILE *stream, int base);
void int_import (int_t r, const uint8_t *bytes, size_t nbytes);
void int_export (uint8_t *bytes, size_t *nbytes, const int_t a);
void int_dump (int_t z);
void int_clear (int_t r);

#define INTVEC_T(__name__, __nelems__, __nlimbs__)                            \
  _ALIGN8 uint8_t                                                             \
      __name__##bytes__[_sizeof_intvec_data (__nelems__, __nlimbs__)];        \
  intvec_t __name__;                                                          \
  _intvec_init (__name__, __nelems__, __nlimbs__, __name__##bytes__);

void intvec_alloc (intvec_ptr r, unsigned int nelems, unsigned int nlimbs);
void intvec_free (intvec_ptr r);
static inline void intvec_set_zero (intvec_t r);
static inline void intvec_set_one (intvec_t r, unsigned int idx);
static inline void intvec_set_ones (intvec_t r);
static inline unsigned int intvec_get_nlimbs (const intvec_t a);
size_t intvec_out_str (FILE *stream, int base, const intvec_t a);
static inline unsigned int intvec_get_nelems (const intvec_t r);
static inline int_ptr intvec_get_elem (const intvec_t a, unsigned int col);
static inline int_srcptr intvec_get_elem_src (const intvec_t a,
                                              unsigned int col);
static inline void intvec_set_elem (intvec_t a, unsigned int col,
                                    const int_t elem);
static inline void intvec_set (intvec_t r, const intvec_t a);
static inline void intvec_set_i64 (intvec_t r, const int64_t *a);
static inline void intvec_set_i32 (intvec_t r, const int32_t *a);
static inline void intvec_set_i16 (intvec_t r, const int16_t *a);
static inline void intvec_get_i16 (int16_t *r, const intvec_t a);
static inline void intvec_get_i32 (int32_t *r, const intvec_t a);
static inline void intvec_get_i64 (int64_t *r, const intvec_t a);
static inline int64_t intvec_get_elem_i64 (const intvec_t a,
                                           unsigned int elem);
static inline void intvec_set_elem_i64 (intvec_t a, unsigned int elem,
                                        int64_t val);
void intvec_mul_sgn_self (intvec_t r, int sgn);
int intvec_eq (const intvec_t a, const intvec_t b);
int intvec_lt (const intvec_t a, const int_t m);
int intvec_gt (const intvec_t a, const int_t m);
int intvec_le (const intvec_t a, const int_t m);
int intvec_ge (const intvec_t a, const int_t m);
void intvec_rshift (intvec_t r, const intvec_t a, unsigned int n);
void intvec_lshift (intvec_t r, const intvec_t a, unsigned int n);
void intvec_rrot (intvec_t r, const intvec_t a, unsigned int n);
void intvec_lrot (intvec_t r, const intvec_t a, unsigned int n);
void intvec_add (intvec_t r, const intvec_t a, const intvec_t b);
void intvec_sub (intvec_t r, const intvec_t a, const intvec_t b);
void intvec_mul (intvec_t r, const intvec_t a, const intvec_t b);
void intvec_scale (intvec_t r, const int_t a, const intvec_t b);
void intvec_div (intvec_t rq, intvec_t rr, const intvec_t a, const intvec_t b);
void intvec_mod (intvec_t r, const intvec_t a, const int_t m);
void intvec_redc (intvec_t r, const intvec_t a, const int_t m);
void intvec_redp (intvec_t r, const intvec_t a, const int_t m);
void intvec_dot (int_t r, const intvec_t a, const intvec_t b);
void intvec_l2sqr (int_t r, const intvec_t a);
void intvec_linf (int_t r, const intvec_t a);
void intvec_urandom_autostable (intvec_t r, int64_t bnd, unsigned int log2,
                                const uint8_t seed[32], uint32_t dom);
void intvec_brandom (intvec_t r, unsigned int k, const uint8_t seed[32],
                     uint32_t dom);
void intvec_grandom (intvec_t r, unsigned int log2o, const uint8_t seed[32],
                     uint32_t dom);
void intvec_urandom (intvec_t r, const int_t mod, unsigned int log2mod,
                     const uint8_t seed[32], uint32_t dom);
void intvec_urandom_bnd (intvec_t r, const int_t lo, const int_t hi,
                         const uint8_t seed[32], uint32_t dom);
void intvec_get_subvec (intvec_t subvec, const intvec_t vec, unsigned int col,
                        unsigned int ncols, unsigned int stride);
void intvec_mul_matvec (intvec_t r, const intmat_t mat, const intvec_t vec);
void intvec_auto (intvec_t r, const intvec_t a);
void intvec_auto_self (intvec_t r);
void intvec_dump (intvec_t z);
void intvec_clear (intvec_t r);

#define INTMAT_T(__name__, __nrows__, __ncols__, __nlimbs__)                  \
  _ALIGN8 uint8_t __name__##bytes__[_sizeof_intmat_data (                     \
      __nrows__, __ncols__, __nlimbs__)];                                     \
  intmat_t __name__;                                                          \
  _intmat_init (__name__, __nrows__, __ncols__, __nlimbs__, __name__##bytes__);

void intmat_alloc (intmat_ptr r, unsigned int nrows, unsigned int ncols,
                   unsigned int nlimbs);
void intmat_free (intmat_ptr r);
static inline unsigned int intmat_get_nlimbs (const intmat_t a);
static inline unsigned int intmat_get_nrows (const intmat_t mat);
static inline unsigned int intmat_get_ncols (const intmat_t mat);
static inline void intmat_set_zero (intmat_t r);
static inline void intmat_set_one (intmat_t r);
static inline void intmat_get_row (intvec_t subvec, const intmat_t mat,
                                   unsigned int row);
static inline void intmat_set_row (intmat_t mat, const intvec_t vec,
                                   unsigned int row);
static inline void intmat_get_col (intvec_t subvec, const intmat_t mat,
                                   unsigned int col);
static inline void intmat_set_col (intmat_t mat, const intvec_t vec,
                                   unsigned int col);
static inline void intmat_get_diag (intvec_t vec, const intmat_t mat,
                                    int diag);
static inline void intmat_set_diag (intmat_t mat, const intvec_t vec,
                                    int diag);
static inline void intmat_get_antidiag (intvec_t vec, const intmat_t mat,
                                        int antidiag);
static inline void intmat_set_antidiag (intmat_t mat, const intvec_t vec,
                                        int antidiag);
static inline void intmat_get_submat (intmat_t submat, const intmat_t mat,
                                      unsigned int row, unsigned int col,
                                      unsigned int nrows, unsigned int ncols,
                                      unsigned int stride_row,
                                      unsigned int stride_col);
static inline void intmat_set_submat (intmat_t mat, const intmat_t submat,
                                      unsigned int row, unsigned int col,
                                      unsigned int nrows, unsigned int ncols,
                                      unsigned int stride_row,
                                      unsigned int stride_col);
static inline int_ptr intmat_get_elem (const intmat_t a, unsigned int row,
                                       unsigned int col);
static inline int_srcptr
intmat_get_elem_src (const intmat_t a, unsigned int row, unsigned int col);
static inline void intmat_set_elem (intmat_t a, unsigned int row,
                                    unsigned int col, const int_t elem);
static inline void intmat_set (intmat_t r, const intmat_t a);
static inline void intmat_set_elem (intmat_t a, unsigned int row,
                                    unsigned int col, const int_t elem);
static inline void intmat_set_elem_i64 (intmat_t a, unsigned int row,
                                        unsigned int col, int64_t elem);
static inline void intmat_set_i64 (intmat_t r, const int64_t *a);
static inline void intmat_get_i64 (int64_t *r, const intmat_t a);
static inline void intmat_set_i32 (intmat_t r, const int32_t *a);
static inline void intmat_get_i32 (int32_t *r, const intmat_t a);
void intmat_brandom (intmat_t r, unsigned int k, const uint8_t seed[32],
                     uint32_t dom);
void intmat_urandom (intmat_t r, const int_t mod, unsigned int log2mod,
                     const uint8_t seed[32], uint32_t dom);
int intmat_eq (const intmat_t a, const intmat_t b);
void intmat_mul_sgn_self (intmat_t r, int sgn);
size_t intmat_out_str (FILE *stream, int base, const intmat_t a);
void intmat_dump (intmat_t mat);
void intmat_clear (intmat_t r);

#define POLYRING_T(__name__, __q__, __d__)                                    \
  polyring_t __name__                                                         \
      = { { (__q__), (__d__), 0, 0, NULL, 0, NULL, NULL, NULL } }

static inline unsigned int polyring_get_deg (const polyring_t ring);
static inline int_srcptr polyring_get_mod (const polyring_t ring);
static inline unsigned int polyring_get_log2q (const polyring_t ring);
static inline unsigned int polyring_get_log2deg (const polyring_t ring);

#define POLY_T(__name__, __ring__)                                            \
  _ALIGN8 uint8_t __name__##bytes__[_sizeof_poly_data (__ring__)];            \
  poly_t __name__;                                                            \
  _poly_init (__name__, __ring__, __name__##bytes__);

/**
 * Allocate a polynomial over a ring.
 *
 * \param r The returned polynomial.
 * \param ring The polynomial ring.
 */
void poly_alloc (poly_ptr r, const polyring_t ring);

/**
 * Free a polynomial.
 *
 * \param r The polynomial to be freed.
 */
void poly_free (poly_ptr r);

static inline void poly_set_zero (poly_t r);
static inline void poly_set_one (poly_t r);
static inline unsigned int poly_get_nlimbs (const poly_t a);
static inline polyring_srcptr poly_get_ring (const poly_t poly);
static inline int_ptr poly_get_coeff (poly_t poly, unsigned int idx);
static inline void poly_set_coeff (poly_t poly, unsigned int idx,
                                   const int_t val);
static inline intvec_ptr poly_get_coeffvec (poly_t poly);
void poly_brandom (poly_t r, unsigned int k, const uint8_t seed[32],
                   uint32_t dom);
void poly_grandom (poly_t r, unsigned int log2o, const uint8_t seed[32],
                   uint32_t dom);
void poly_urandom (poly_t r, const int_t mod, unsigned int log2mod,
                   const uint8_t seed[32], uint32_t dom);
void poly_urandom_bnd (poly_t r, const int_t lo, const int_t hi,
                       const uint8_t seed[32], uint32_t dom);
void poly_urandom_autostable (poly_t r, int64_t bnd, unsigned int log2,
                              const uint8_t seed[32], uint32_t dom);
int poly_eq (poly_t a, poly_t b);
void poly_set (poly_t r, const poly_t a);
void poly_add (poly_t r, poly_t a, poly_t b, int crt);
void poly_sub (poly_t r, poly_t a, poly_t b, int crt);
void poly_scale (poly_t r, const int_t a, poly_t b);
void poly_mul (poly_t r, poly_t a, poly_t b);
void poly_rshift (poly_t r, poly_t a, unsigned int n);
void poly_lshift (poly_t r, poly_t a, unsigned int n);
void poly_rrot (poly_t r, poly_t a, unsigned int n);
void poly_lrot (poly_t r, poly_t a, unsigned int n);
void poly_mod (poly_t r, poly_t a);
void poly_redc (poly_t r, poly_t a);
void poly_redp (poly_t r, poly_t a);
void poly_tocrt (poly_t r);
void poly_addmul (poly_t r, poly_t a, poly_t b, int crt);
void poly_submul (poly_t r, poly_t a, poly_t b, int crt);
void poly_addmul2 (poly_t r, polymat_t a, polyvec_t b, int crt);
void poly_submul2 (poly_t r, polymat_t a, polyvec_t b, int crt);
void poly_adddot (poly_t r, polyvec_t a, polyvec_t b, int crt);
void poly_adddot2 (poly_t r, spolyvec_t a, polyvec_t b, int crt);
void poly_subdot (poly_t r, polyvec_t a, polyvec_t b, int crt);
void poly_fromcrt (poly_t r);
void poly_dcompress_power2round (poly_t r, poly_t a,
                                 const dcompress_params_t params);
void poly_dcompress_decompose (poly_t r1, poly_t r0, poly_t r,
                               const dcompress_params_t params);
void poly_dcompress_use_ghint (poly_t ret, poly_t y, poly_t r,
                               const dcompress_params_t params);
void poly_dcompress_make_ghint (poly_t ret, poly_t z, poly_t r,
                                const dcompress_params_t params);
void poly_l2sqr (int_t r, poly_t a);
void poly_linf (int_t r, poly_t a);
static inline void poly_set_coeffvec (poly_t r, const intvec_t v);
static inline void poly_set_coeffvec2 (poly_t r, intvec_ptr v);
static inline void poly_set_coeffvec_i64 (poly_t r, const int64_t *a);
static inline void poly_set_coeffvec_i32 (poly_t r, const int32_t *a);
static inline void poly_set_coeffvec_i16 (poly_t r, const int16_t *a);
static inline void poly_get_coeffvec_i64 (int64_t *r, poly_t a);
static inline void poly_get_coeffvec_i32 (int32_t *r, poly_t a);
void poly_auto (poly_t r, poly_t a);
void poly_auto_self (poly_t r);
void poly_tracemap (poly_t r, poly_t a);
void poly_toisoring (polyvec_t vec, poly_t a);
void poly_fromisoring (poly_t a, polyvec_t vec);
size_t poly_out_str (FILE *stream, int base, poly_t a);
void poly_dump (poly_t a);

#define POLYVEC_T(__name__, __ring__, __nelems__)                             \
  _ALIGN8 uint8_t                                                             \
      __name__##bytes__[_sizeof_polyvec_data (__ring__, __nelems__)];         \
  polyvec_t __name__;                                                         \
  _polyvec_init (__name__, __ring__, __nelems__, __name__##bytes__)

void polyvec_alloc (polyvec_ptr r, const polyring_t ring, unsigned int nelems);
void polyvec_free (polyvec_ptr r);
static inline void polyvec_fill (polyvec_t r, poly_t a);
static inline void polyvec_set_zero (polyvec_t r);
static inline void polyvec_set_one (polyvec_t r, unsigned int idx);
static inline void polyvec_set_ones (polyvec_t r);
static inline unsigned int polyvec_get_nlimbs (const polyvec_t a);
static inline unsigned int polyvec_get_nelems (const polyvec_t a);
static inline polyring_srcptr polyvec_get_ring (const polyvec_t a);
static inline poly_ptr polyvec_get_elem (const polyvec_t a, unsigned int elem);
static inline poly_srcptr polyvec_get_elem_src (const polyvec_t a,
                                                unsigned int elem);
static inline void polyvec_set_elem (polyvec_t a, unsigned int idx,
                                     const poly_t elem);
static inline void polyvec_set (polyvec_t r, const polyvec_t a);
static inline void polyvec_set_coeffvec_i64 (polyvec_t r, const int64_t *a);
static inline void polyvec_set_coeffvec_i32 (polyvec_t r, const int32_t *a);
static inline void polyvec_get_coeffvec_i32 (int32_t *r, const polyvec_t a);
static inline void polyvec_get_coeffvec_i64 (int64_t *r, const polyvec_t a);
void polyvec_get_subvec (polyvec_t subvec, const polyvec_t vec,
                         unsigned int elem, unsigned int nelems,
                         unsigned int stride);
static inline void polyvec_set_coeffvec (polyvec_t r, const intvec_t v);
static inline void polyvec_set_coeffvec2 (polyvec_t r, intvec_ptr v);
int polyvec_eq (polyvec_t a, polyvec_t b);
void polyvec_rshift (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_lshift (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_rrot (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_lrot (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_add (polyvec_t r, polyvec_t a, polyvec_t b, int crt);
void polyvec_sub (polyvec_t r, polyvec_t a, polyvec_t b, int crt);
// XXXvoid polyvec_mul (polyvec_t r, polyvec_t a, polyvec_t b);
void polyvec_scale (polyvec_t r, const int_t a, polyvec_t b);
void polyvec_addscale (polyvec_t r, const int_t a, polyvec_t b, int crt);
void polyvec_subscale (polyvec_t r, const int_t a, polyvec_t b, int crt);
void polyvec_scale2 (polyvec_t r, poly_t a, polyvec_t b);
void polyvec_addscale2 (polyvec_t r, poly_t a, polyvec_t b, int crt);
void polyvec_subscale2 (polyvec_t r, poly_t a, polyvec_t b, int crt);
void polymat_rrot (polymat_t r, polymat_t a, unsigned int n);
void polymat_rrotdiag (polymat_t r, polymat_t a, unsigned int n);
void polymat_lrot (polymat_t r, polymat_t a, unsigned int n);
void polymat_lrotdiag (polymat_t r, polymat_t a, unsigned int n);
void polyvec_tocrt (polyvec_t r);
void polyvec_fromcrt (polyvec_t r);
void polyvec_mod (polyvec_t r, polyvec_t a);
void polyvec_redc (polyvec_t r, polyvec_t a);
void polyvec_redp (polyvec_t r, polyvec_t a);
void poly_neg (poly_t r, poly_t b);
void polyvec_auto_self (polyvec_t r);
void polyvec_auto (polyvec_t r, polyvec_t a);
void polyvec_urandom_autostable (polyvec_t r, int64_t bnd, unsigned int log2,
                                 const uint8_t seed[32], uint32_t dom);
void polyvec_dcompress_power2round (polyvec_t r, polyvec_t a,
                                    const dcompress_params_t params);
void polyvec_dcompress_decompose (polyvec_t r1, polyvec_t r0, polyvec_t r,
                                  const dcompress_params_t params);
void polyvec_dcompress_use_ghint (polyvec_t ret, polyvec_t y, polyvec_t r,
                                  const dcompress_params_t params);
void polyvec_dcompress_make_ghint (polyvec_t ret, polyvec_t z, polyvec_t r,
                                   const dcompress_params_t params);
void polyvec_dot (poly_t r, polyvec_t a, polyvec_t b);
void polyvec_dot2 (poly_t r, spolyvec_t a, polyvec_t b);
void polyvec_linf (int_t r, polyvec_t a);
void polyvec_l2sqr (int_t r, polyvec_t a);
void polyvec_grandom (polyvec_t r, unsigned int log2o, const uint8_t seed[32],
                      uint32_t dom);
void polyvec_brandom (polyvec_t r, unsigned int k, const uint8_t seed[32],
                      uint32_t dom);
void polyvec_urandom (polyvec_t r, const int_t mod, unsigned int log2mod,
                      const uint8_t seed[32], uint32_t dom);
void polyvec_urandom_bnd (polyvec_t r, const int_t lo, const int_t hi,
                          const uint8_t seed[32], uint32_t dom);
void polyvec_mul (polyvec_t r, polymat_t a, polyvec_t b);
void polyvec_muldiag (polyvec_t r, polymat_t diag, polyvec_t b);
void polyvec_mul2 (polyvec_t r, polyvec_t a, polymat_t b);
void polyvec_muldiag2 (polyvec_t r, polyvec_t a, polymat_t diag);
void polyvec_addmul (polyvec_t r, polymat_t a, polyvec_t b, int crt);
void polyvec_addmul2 (polyvec_t r, polyvec_t a, polymat_t b, int crt);
void polyvec_submul (polyvec_t r, polymat_t a, polyvec_t b, int crt);
void polyvec_submul2 (polyvec_t r, polyvec_t a, polymat_t b, int crt);
void poly_addscale (poly_t r, int_t a, poly_t b, int crt);
void poly_subscale (poly_t r, int_t a, poly_t b, int crt);
void polyvec_addrshift (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_subrshift (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_addlshift (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_sublshift (polyvec_t r, polyvec_t a, unsigned int n);
void polyvec_toisoring (polyvec_t vec, polyvec_t a);
void polyvec_fromisoring (polyvec_t a, polyvec_t vec);
void polyvec_elem_mul (polyvec_t r, polyvec_t a, polyvec_t b);
size_t polyvec_out_str (FILE *stream, int base, polyvec_t a);
void polyvec_dump (polyvec_t vec);

#define POLYMAT_T(__name__, __ring__, __nrows__, __ncols__)                   \
  _ALIGN8 uint8_t __name__##bytes__[_sizeof_polymat_data (                    \
      __ring__, __nrows__, __ncols__)];                                       \
  polymat_t __name__;                                                         \
  _polymat_init (__name__, __ring__, __nrows__, __ncols__, __name__##bytes__)

void polymat_alloc (polymat_ptr r, const polyring_t ring, unsigned int nrows,
                    unsigned int ncols);
void polymat_free (polymat_ptr r);
static inline void polymat_fill (polymat_t r, poly_t a);
static inline void polymat_set_zero (polymat_t r);
static inline void polymat_set_one (polymat_t r);
static inline unsigned int polymat_get_nlimbs (const polymat_t a);
static inline unsigned int polymat_get_nrows (const polymat_t mat);
static inline unsigned int polymat_get_ncols (const polymat_t mat);
static inline poly_ptr polymat_get_elem (const polymat_t a, unsigned int row,
                                         unsigned int col);
static inline poly_srcptr
polymat_get_elem_src (const polymat_t a, unsigned int row, unsigned int col);
static inline void polymat_set_elem (polymat_t a, unsigned int row,
                                     unsigned int col, const poly_t elem);
static inline polyring_srcptr polymat_get_ring (const polymat_t a);
static inline void polymat_get_row (polyvec_t subvec, const polymat_t mat,
                                    unsigned int row);
static inline void polymat_set_row (polymat_t mat, const polyvec_t vec,
                                    unsigned int row);
static inline void polymat_get_col (polyvec_t subvec, const polymat_t mat,
                                    unsigned int col);
static inline void polymat_set_col (polymat_t mat, const polyvec_t vec,
                                    unsigned int col);
static inline void polymat_get_diag (polyvec_t subvec, const polymat_t mat,
                                     int diag);
static inline void polymat_set_diag (polymat_t mat, const polyvec_t vec,
                                     int diag);
static inline void polymat_get_antidiag (polyvec_t subvec, const polymat_t mat,
                                         int antidiag);
static inline void polymat_set_antidiag (polymat_t mat, const polyvec_t vec,
                                         int antidiag);
int polymat_is_upperdiag (polymat_t a);
void polymat_subdiags_set_zero (polymat_t r);
static inline void polymat_get_submat (polymat_t submat, const polymat_t mat,
                                       unsigned int row, unsigned int col,
                                       unsigned int nrows, unsigned int ncols,
                                       unsigned int stride_row,
                                       unsigned int stride_col);
static inline void polymat_set_submat (polymat_t mat, const polymat_t submat,
                                       unsigned int row, unsigned int col,
                                       unsigned int nrows, unsigned int ncols,
                                       unsigned int stride_row,
                                       unsigned int stride_col);
static inline void polymat_set (polymat_t r, const polymat_t a);
static inline void polymat_set_i64 (polymat_t r, const int64_t *a);
static inline void polymat_set_i32 (polymat_t r, const int32_t *a);
static inline void polymat_get_i64 (int64_t *r, const polymat_t a);
static inline void polymat_get_i32 (int32_t *r, const polymat_t a);
void polymat_fromcrt (polymat_t r);
void polymat_fromcrtdiag (polymat_t r);
void polymat_tocrt (polymat_t r);
void polymat_tocrtdiag (polymat_t r);
void polymat_mod (polymat_t r, polymat_t a);
void polymat_moddiag (polymat_t r, polymat_t a);
void polymat_redc (polymat_t r, polymat_t a);
void polymat_redp (polymat_t r, polymat_t a);
void polymat_add (polymat_t r, polymat_t a, polymat_t b, int crt);
void polymat_sub (polymat_t r, polymat_t a, polymat_t b, int crt);
void polymat_adddiag (polymat_t r, polymat_t a, polymat_t b, int crt);
void polymat_subdiag (polymat_t r, polymat_t a, polymat_t b, int crt);
void polymat_addscalediag (polymat_t r, const int_t a, polymat_t b, int crt);
void polymat_subscalediag (polymat_t r, const int_t a, polymat_t b, int crt);
void polymat_scale (polymat_t r, const int_t a, polymat_t b);
void polymat_scalediag (polymat_t r, const int_t a, polymat_t b);
void polymat_addscale (polymat_t r, const int_t a, polymat_t b, int crt);
void polymat_subscale (polymat_t r, const int_t a, polymat_t b, int crt);
void polymat_scale2 (polymat_t r, poly_t a, polymat_t b);
void polymat_scalediag2 (polymat_t r, poly_t a, polymat_t b);
void polymat_addscale2 (polymat_t r, poly_t a, polymat_t b, int crt);
void polymat_addscalediag2 (polymat_t r, poly_t a, polymat_t b, int crt);
void polymat_subscale2 (polymat_t r, poly_t a, polymat_t b, int crt);
void polymat_subscalediag2 (polymat_t r, poly_t a, polymat_t b, int crt);
void polymat_urandom (polymat_t r, const int_t mod, unsigned int log2mod,
                      const uint8_t seed[32], uint32_t dom);
void polymat_brandom (polymat_t r, unsigned int k, const uint8_t seed[32],
                      uint32_t dom);
void polymat_auto (polymat_t r, polymat_t a);
size_t polymat_out_str (FILE *stream, int base, const polymat_t a);
void polymat_dump (polymat_t mat);

void spolyvec_sort (spolyvec_ptr r);
void spolyvec_alloc (spolyvec_ptr r, const polyring_t ring,
                     unsigned int nelems, unsigned int nelems_max);
void spolyvec_set (spolyvec_ptr r, spolyvec_ptr a);
void spolyvec_redc (spolyvec_ptr r);
void spolyvec_redp (spolyvec_ptr r);
void spolyvec_add (spolyvec_t r, spolyvec_t a, spolyvec_t b, int crt);
void spolyvec_fromcrt (spolyvec_t r);
void spolyvec_lrot (spolyvec_t r, spolyvec_t b, unsigned int n);
void spolyvec_mod (spolyvec_ptr r, spolyvec_ptr b);
void spolyvec_scale (spolyvec_t r, const int_t a, spolyvec_t b);
void spolyvec_scale2 (spolyvec_t r, poly_t a, spolyvec_t b);
void spolyvec_urandom (spolyvec_t r, const int_t mod, unsigned int log2mod,
                       const uint8_t seed[32], uint32_t dom);
void spolyvec_brandom (spolyvec_t r, unsigned int k, const uint8_t seed[32],
                       uint32_t dom);
poly_ptr spolyvec_insert_elem (spolyvec_ptr r, unsigned int elem);
void spolyvec_free (spolyvec_ptr r);
poly_ptr spolyvec_get_elem2 (spolyvec_ptr a, unsigned int elem);
size_t spolyvec_out_str (FILE *stream, int base, spolyvec_t a);
void spolyvec_dump (spolyvec_t vec);

void spolymat_alloc (spolymat_ptr r, const polyring_t ring, unsigned int nrows,
                     unsigned int ncols, unsigned int nelems_max);
poly_ptr spolymat_get_elem2 (spolymat_ptr a, unsigned int row,
                             unsigned int col);
void spolymat_scale (spolymat_t r, const int_t a, spolymat_t b);
void spolymat_scale2 (spolymat_t r, poly_t a, spolymat_t b);
poly_ptr spolymat_insert_elem (spolymat_ptr r, unsigned int row,
                               unsigned int col);
void spolymat_urandom (spolymat_t r, const int_t mod, unsigned int log2mod,
                       const uint8_t seed[32], uint32_t dom);
void spolymat_brandom (spolymat_t r, unsigned int k, const uint8_t seed[32],
                       uint32_t dom);
void spolymat_add (spolymat_t r, spolymat_t a, spolymat_t b, int crt);
void polyvec_mulsparse (polyvec_t r, spolymat_t a, polyvec_t b);
void spolymat_redc (spolymat_ptr r);
void spolymat_redp (spolymat_ptr r);
int spolymat_is_upperdiag (spolymat_ptr r);
void spolymat_sort (spolymat_ptr r);
void spolymat_mod (spolymat_ptr r, spolymat_ptr b);
void spolymat_lrot (spolymat_t r, spolymat_t b, unsigned int n);
void spolymat_set (spolymat_ptr r, spolymat_ptr a);
void spolymat_fromcrt (spolymat_t r);
void spolymat_free (spolymat_ptr r);
void spolymat_dump (spolymat_t mat);
size_t spolymat_out_str (FILE *stream, int base, spolymat_t a);

void quad_toisoring (polymat_ptr R2[], polyvec_ptr r1[], poly_ptr r0[],
                     polymat_ptr R2prime, polyvec_ptr r1prime,
                     poly_ptr r0prime);
void lin_toisoring (polymat_t r1, polyvec_t r0, polymat_t r1prime,
                    polyvec_t r0prime);

#define CODER_STATE_T(__name__)                                               \
  coder_state_t __name__ = { { NULL, NULL, 0, 0 } }
void coder_enc_begin (coder_state_t state, uint8_t *out);
void coder_dec_begin (coder_state_t state, const uint8_t *in);
void coder_enc_end (coder_state_t state);
int coder_dec_end (coder_state_t state);
unsigned int coder_get_offset (coder_state_t state);
void coder_enc_urandom (coder_state_t state, const intvec_t v, const int_t m,
                        unsigned int mbits);
void coder_enc_bytes (coder_state_t state, const uint8_t *bytes,
                      unsigned int nbytes);
int coder_dec_urandom (coder_state_t state, intvec_t v, const int_t m,
                       unsigned int mbits);
void coder_enc_grandom (coder_state_t state, const intvec_t v,
                        unsigned int log2o);
void coder_enc_ghint (coder_state_t state, const intvec_t ghint);
int coder_dec_bytes (coder_state_t state, uint8_t *bytes, unsigned int nbytes);
void coder_dec_grandom (coder_state_t state, intvec_t v, unsigned int log2o);
void coder_dec_ghint (coder_state_t state, intvec_t ghint);

void coder_enc_urandom2 (coder_state_t state, poly_t v, const int_t m,
                         unsigned int mbits);
int coder_dec_urandom2 (coder_state_t state, poly_t v, const int_t m,
                        unsigned int mbits);
void coder_enc_grandom2 (coder_state_t state, poly_t v, unsigned int log2o);
void coder_enc_ghint2 (coder_state_t state, poly_t ghint);
void coder_dec_grandom2 (coder_state_t state, poly_t v, unsigned int log2o);
void coder_dec_ghint2 (coder_state_t state, poly_t ghint);

void coder_enc_urandom3 (coder_state_t state, polyvec_t v, const int_t m,
                         unsigned int mbits);
int coder_dec_urandom3 (coder_state_t state, polyvec_t v, const int_t m,
                        unsigned int mbits);
void coder_enc_grandom3 (coder_state_t state, polyvec_t v, unsigned int log2o);
void coder_enc_ghint3 (coder_state_t state, polyvec_t ghint);
void coder_dec_grandom3 (coder_state_t state, polyvec_t v, unsigned int log2o);
void coder_dec_ghint3 (coder_state_t state, polyvec_t ghint);
void coder_enc_urandom4 (coder_state_t state, polymat_t v, const int_t m,
                         unsigned int mbits);
int coder_dec_urandom4 (coder_state_t state, polymat_t v, const int_t m,
                        unsigned int mbits);
void coder_enc_urandom4diag (coder_state_t state, polymat_t v, const int_t m,
                             unsigned int mbits);
int coder_dec_urandom4diag (coder_state_t state, polymat_t v, const int_t m,
                            unsigned int mbits);
void coder_enc_urandom5 (coder_state_t state, spolymat_t v, const int_t m,
                         unsigned int mbits);
void coder_dec_urandom5 (coder_state_t state, spolymat_t v, const int_t m,
                         unsigned int mbits);
void coder_enc_urandom6 (coder_state_t state, spolyvec_t v, const int_t m,
                         unsigned int mbits);
void coder_dec_urandom6 (coder_state_t state, spolyvec_t v, const int_t m,
                         unsigned int mbits);

int rej_standard (rng_state_t state, const intvec_t z, const intvec_t v,
                  const int_t scM, const int_t sigma2);
int rej_bimodal (rng_state_t state, const intvec_t z, const intvec_t v,
                 const int_t scM, const int_t sigma2);

static inline unsigned int dcompress_get_d (const dcompress_params_t params);
static inline int_srcptr dcompress_get_gamma (const dcompress_params_t params);
static inline int_srcptr dcompress_get_m (const dcompress_params_t params);
static inline unsigned int
dcompress_get_log2m (const dcompress_params_t params);
void dcompress_decompose (intvec_t r1, intvec_t r0, const intvec_t r,
                          const dcompress_params_t params);
void dcompress_power2round (intvec_t ret, const intvec_t r,
                            const dcompress_params_t params);
void dcompress_use_ghint (intvec_t ret, const intvec_t y, const intvec_t r,
                          const dcompress_params_t params);
void dcompress_make_ghint (intvec_t ret, const intvec_t z, const intvec_t r,
                           const dcompress_params_t params);

void abdlop_keygen (polymat_t A1, polymat_t A2prime, polymat_t Bprime,
                    const uint8_t seed[32], const abdlop_params_t params);

void abdlop_commit (polyvec_t tA1, polyvec_t tA2, polyvec_t tB, polyvec_t s1,
                    polyvec_t m, polyvec_t s2, polymat_t A1, polymat_t A2prime,
                    polymat_t Bprime, const abdlop_params_t params);
void abdlop_enccomm (uint8_t *buf, size_t *buflen, polyvec_t tA1, polyvec_t tB,
                     const abdlop_params_t params);
void abdlop_hashcomm (uint8_t hash[32], polyvec_t tA1, polyvec_t tB,
                      const abdlop_params_t params);
void abdlop_prove (uint8_t hash[32], poly_t c, polyvec_t z1, polyvec_t z21,
                   polyvec_t h, polyvec_t tA2, polyvec_t s1, polyvec_t s2,
                   polymat_t A1, polymat_t A2prime, const uint8_t seed[32],
                   const abdlop_params_t params);
int abdlop_verify (uint8_t hash[32], poly_t c, polyvec_t z1, polyvec_t z21,
                   polyvec_t h, polyvec_t tA1, polymat_t A1, polymat_t A2prime,
                   const abdlop_params_t params);

void lnp_quad_prove (uint8_t hash[32], polyvec_t tB, poly_t c, polyvec_t z1,
                     polyvec_t z21, polyvec_t h, polyvec_t s1, polyvec_t m,
                     polyvec_t s2, polyvec_t tA2, polymat_t A1,
                     polymat_t A2prime, polymat_t Bprime, spolymat_t R2,
                     spolyvec_t r1, const uint8_t seed[32],
                     const abdlop_params_t params);
int lnp_quad_verify (uint8_t hash[32], poly_t c, polyvec_t z1, polyvec_t z21,
                     polyvec_t h, polyvec_t tA1, polyvec_t tB, polymat_t A1,
                     polymat_t A2prime, polymat_t Bprime, spolymat_t R2,
                     spolyvec_t r1, poly_t r0, const abdlop_params_t params);

void lnp_quad_many_prove (uint8_t hash[32], polyvec_t tB, poly_t c,
                          polyvec_t z1, polyvec_t z21, polyvec_t h,
                          polyvec_t s1, polyvec_t m, polyvec_t s2,
                          polyvec_t tA2, polymat_t A1, polymat_t A2prime,
                          polymat_t Bprime, spolymat_ptr R2i[],
                          spolyvec_ptr r1i[], unsigned int N,
                          const uint8_t seed[32],
                          const abdlop_params_t params);
int lnp_quad_many_verify (uint8_t hash[32], poly_t c, polyvec_t z1,
                          polyvec_t z21, polyvec_t h, polyvec_t tA1,
                          polyvec_t tB, polymat_t A1, polymat_t A2prime,
                          polymat_t Bprime, spolymat_ptr R2i[],
                          spolyvec_ptr r1i[], poly_ptr r0i[], unsigned int N,
                          const abdlop_params_t params);

void lnp_quad_eval_prove (uint8_t hash[32], polyvec_t tB, polyvec_t h,
                          poly_t c, polyvec_t z1, polyvec_t z21,
                          polyvec_t hint, polyvec_t s1, polyvec_t m,
                          polyvec_t s2, polyvec_t tA2, polymat_t A1,
                          polymat_t A2prime, polymat_t Bprime,
                          spolymat_ptr R2i[], spolyvec_ptr r1i[],
                          unsigned int N, spolymat_ptr Rprime2i[],
                          spolyvec_ptr rprime1i[], poly_ptr rprime0i[],
                          unsigned int M, const uint8_t seed[32],
                          const lnp_quad_eval_params_t params);
int lnp_quad_eval_verify (uint8_t hash[32], polyvec_t h, poly_t c,
                          polyvec_t z1, polyvec_t z21, polyvec_t hint,
                          polyvec_t tA1, polyvec_t tB, polymat_t A1,
                          polymat_t A2prime, polymat_t Bprime,
                          spolymat_ptr R2i[], spolyvec_ptr r1i[],
                          poly_ptr r0i[], unsigned int N,
                          spolymat_ptr Rprime2i[], spolyvec_ptr rprime1i[],
                          poly_ptr rprime0i[], unsigned int M,
                          const lnp_quad_eval_params_t params);

void lnp_tbox_prove (uint8_t hash[32], polyvec_t tB, polyvec_t h, poly_t c,
                     polyvec_t z1, polyvec_t z21, polyvec_t hint, polyvec_t z3,
                     polyvec_t z4, polyvec_t s1, polyvec_t m, polyvec_t s2,
                     polyvec_t tA2, polymat_t A1, polymat_t A2prime,
                     polymat_t Bprime, spolymat_ptr R2i[], spolyvec_ptr r1i[],
                     unsigned int N, spolymat_ptr Rprime2i[],
                     spolyvec_ptr rprime1i[], poly_ptr rprime0i[],
                     unsigned int M, polymat_ptr Esi[], polymat_ptr Emi[],
                     polyvec_ptr vi[], polymat_t Ps, polymat_t Pm, polyvec_t f,
                     polymat_t Ds, polymat_t Dm, polyvec_t u,
                     const uint8_t seed[32], const lnp_tbox_params_t params);

int lnp_tbox_verify (uint8_t hash[32], polyvec_t h, poly_t c, polyvec_t z1,
                     polyvec_t z21, polyvec_t hint, polyvec_t z3, polyvec_t z4,
                     polyvec_t tA1, polyvec_t tB, polymat_t A1,
                     polymat_t A2prime, polymat_t Bprime, spolymat_ptr R2i[],
                     spolyvec_ptr r1i[], poly_ptr r0i[], unsigned int N,
                     spolymat_ptr Rprime2i[], spolyvec_ptr rprime1i[],
                     poly_ptr rprime0i[], unsigned int M, polymat_ptr Esi[],
                     polymat_ptr Emi[], polyvec_ptr vi[], polymat_t Ps,
                     polymat_t Pm, polyvec_t f, polymat_t Ds, polymat_t Dm,
                     polyvec_t u, const lnp_tbox_params_t params);

void lnp_prover_init (lnp_prover_state_t state, const uint8_t ppseed[32],
                      const lnp_tbox_params_t params);
void lnp_verifier_init (lnp_verifier_state_t state, const uint8_t ppseed[32],
                        const lnp_tbox_params_t params);

void lnp_prover_set_witness (lnp_prover_state_t state, polyvec_t s1,
                             polyvec_t m);
void lnp_prover_set_statement_quadeqs (lnp_prover_state_t state,
                                       spolymat_ptr R2[], spolyvec_ptr r1[],
                                       poly_ptr r0[], unsigned int N);
void lnp_verifier_set_statement_quadeqs (lnp_verifier_state_t state,
                                         spolymat_ptr R2[], spolyvec_ptr r1[],
                                         poly_ptr r0[], unsigned int N);
void lnp_prover_set_statement_evaleqs (lnp_prover_state_t state,
                                       spolymat_ptr R2prime[],
                                       spolyvec_ptr r1prime[],
                                       poly_ptr r0prime[], unsigned int M);
void lnp_verifier_set_statement_evaleqs (lnp_verifier_state_t state,
                                         spolymat_ptr R2prime[],
                                         spolyvec_ptr r1prime[],
                                         poly_ptr r0prime[], unsigned int M);
void lnp_prover_set_statement_l2 (lnp_prover_state_t state, polymat_ptr Es[],
                                  polymat_ptr Em[], polyvec_ptr v[]);
void lnp_verifier_set_statement_l2 (lnp_verifier_state_t state,
                                    polymat_ptr Es[], polymat_ptr Em[],
                                    polyvec_ptr v[]);
void lnp_prover_set_statement_bin (lnp_prover_state_t state, polymat_t Ps,
                                   polymat_t Pm, polyvec_t f);
void lnp_verifier_set_statement_bin (lnp_verifier_state_t state, polymat_t Ps,
                                     polymat_t Pm, polyvec_t f);
void lnp_prover_set_statement_arp (lnp_prover_state_t state, polymat_t Ds,
                                   polymat_t Dm, polyvec_t u);
void lnp_verifier_set_statement_arp (lnp_verifier_state_t state, polymat_t Ds,
                                     polymat_t Dm, polyvec_t u);

void lnp_prover_prove (lnp_prover_state_t state_, uint8_t *proof, size_t *len,
                       const uint8_t seed[32]);
int lnp_verifier_verify (lnp_verifier_state_t state_, const uint8_t *proof,
                         size_t *len);

void lnp_prover_clear (lnp_prover_state_t state);
void lnp_verifier_clear (lnp_verifier_state_t state);

void signer_keygen (uint8_t sk[1281], uint8_t pk[897]);
void signer_init (signer_state_t state, const uint8_t pubkey[897],
                  const uint8_t privkey[1281]);
int signer_sign (signer_state_t state, uint8_t *blindsig, size_t *blindsiglen,
                 const uint8_t *masked_msg, size_t maked_msglen);
void signer_clear (signer_state_t state);

void verifier_init (verifier_state_t state, const uint8_t pubkey[897]);
int verifier_vrfy (verifier_state_t state, const uint8_t m[512 / 8],
                   const uint8_t *sig, size_t siglen);
void verifier_clear (verifier_state_t state);

void user_init (user_state_t state, const uint8_t pubkey[897]);
void user_maskmsg (user_state_t state, uint8_t *masked_msg,
                   size_t *masked_msglen, const uint8_t msg[512 / 8]);
int user_sign (user_state_t state, uint8_t *sig, size_t *siglen,
               const uint8_t *blindsig, size_t blindsiglen);
void user_clear (user_state_t state);

unsigned long lin_params_get_prooflen (const lin_params_t params);

void lin_prover_init (lin_prover_state_t state, const uint8_t ppseed[32],
                      const lin_params_t params);
void lin_prover_set_statement_A (lin_prover_state_t state, polymat_t A);
void lin_prover_set_statement_t (lin_prover_state_t state, polyvec_t t);
void lin_prover_set_statement (lin_prover_state_t state, polymat_t A,
                               polyvec_t t);
void lin_prover_set_witness (lin_prover_state_t state, polyvec_t w);
void lin_prover_prove (lin_prover_state_t state, uint8_t *proof, size_t *len,
                       const uint8_t coins[32]);
void lin_prover_clear (lin_prover_state_t state);
void lin_verifier_init (lin_verifier_state_t state, const uint8_t ppseed[32],
                        const lin_params_t params);
void lin_verifier_set_statement_A (lin_verifier_state_t state, polymat_t A);
void lin_verifier_set_statement_t (lin_verifier_state_t state, polyvec_t t);
void lin_verifier_set_statement (lin_verifier_state_t state, polymat_t A,
                                 polyvec_t t);
int lin_verifier_verify (lin_verifier_state_t state, const uint8_t *proof,
                         size_t *len);
void lin_verifier_clear (lin_verifier_state_t state);

void print_stopwatch_user_maskmsg (unsigned int indent);
void print_stopwatch_signer_sign (unsigned int indent);
void print_stopwatch_user_sign (unsigned int indent);
void print_stopwatch_verifier_vrfy (unsigned int indent);
void print_stopwatch_lnp_prover_prove (unsigned int indent);
void print_stopwatch_lnp_verifier_verify (unsigned int indent);
void print_stopwatch_lnp_tbox_prove (unsigned int indent);
void print_stopwatch_lnp_tbox_verify (unsigned int indent);
void print_stopwatch_lnp_quad_eval_prove (unsigned int indent);
void print_stopwatch_lnp_quad_eval_verify (unsigned int indent);
void print_stopwatch_lnp_quad_many_prove (unsigned int indent);
void print_stopwatch_lnp_quad_many_verify (unsigned int indent);
void print_stopwatch_lnp_quad_prove (unsigned int indent);
void print_stopwatch_lnp_quad_verify (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_tg (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_z34 (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_auto (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_beta3 (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_beta4 (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_upsilon (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_bin (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_l2 (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_z4 (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_z3 (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_sz_auto (unsigned int indent);
void print_stopwatch_lnp_tbox_prove_hi (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_beta3 (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_beta4 (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_upsilon (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_bin (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_l2 (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_z4 (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_z3 (unsigned int indent);
void print_stopwatch_lnp_tbox_verify_sz_auto (unsigned int indent);

void falcon_redc (int16_t c[512]);
void falcon_add (int16_t c[512], const int16_t a[512], const int16_t b[512]);
void falcon_mul (int16_t c[512], const int16_t a[512], const int16_t b[512]);
void falcon_keygen (uint8_t sk[1281], uint8_t pk[897]);
void falcon_decode_pubkey (int16_t h[512], const uint8_t pk[897]);
void falcon_preimage_sample (int16_t s1[512], int16_t s2[512],
                             const int16_t t[512], const uint8_t sk[1281]);

/********************************************************************
 * 3.2 Internal functions and macros
 */

/* XXX internal sizeof(limb_t) * 8 */
#define NBITS_LIMB ((limb_t)(sizeof (limb_t) << 3))

/* XXX internal */
#define CEIL(x, y) (((x) + (y) - 1) / (y))
#define FLOOR(x, y) ((x) / (y))

#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

#define ERR(expr, fmt, ...)                                                   \
  do                                                                          \
    {                                                                         \
      if (UNLIKELY ((expr)))                                                  \
        {                                                                     \
          fprintf (stderr, "lazer: error: " fmt "\n", __VA_ARGS__);           \
          abort ();                                                           \
        }                                                                     \
    }                                                                         \
  while (0)

#define WARN(expr, fmt, ...)                                                  \
  do                                                                          \
    {                                                                         \
      if (UNLIKELY ((expr)))                                                  \
        fprintf (stderr, "lazer: warning: " fmt "\n", __VA_ARGS__);           \
    }                                                                         \
  while (0)

#if ASSERT == ASSERT_ENABLED
#define ASSERT_ERR(expr)                                                      \
  ERR (!(expr), "assertion %s failed (%s:%d).", #expr, __FILE__, __LINE__)
#define ASSERT_WARN(expr)                                                     \
  WARN (!(expr), "assertion %s failed (%s:%d).", #expr, __FILE__, __LINE__)
#else
#define ASSERT_ERR(expr) (void)0
#define ASSERT_WARN(expr) (void)0
#endif

#define _VEC_FOREACH_ELEM(__vec__, __it__)                                    \
  for ((__it__) = 0; (__it__) < (__vec__)->nelems; (__it__)++)

#define _MAT_FOREACH_ROW(__mat__, __itr__)                                    \
  for ((__itr__) = 0; (__itr__) < (__mat__)->nrows; (__itr__)++)

#define _MAT_FOREACH_COL(__mat__, __itc__)                                    \
  for ((__itc__) = 0; (__itc__) < (__mat__)->ncols; (__itc__)++)

#define _MAT_FOREACH_ELEM(__mat__, __itr__, __itc__)                          \
  for ((__itr__) = 0; (__itr__) < (__mat__)->nrows; (__itr__)++)              \
    for ((__itc__) = 0; (__itc__) < (__mat__)->ncols; (__itc__)++)

#define _SVEC_FOREACH_ELEM(__vec__, __ite__)                                  \
  for ((__ite__) = 0; (__ite__) < (__vec__)->nelems; (__ite__)++)

#define _SMAT_FOREACH_ELEM(__mat__, __ite__)                                  \
  for ((__ite__) = 0; (__ite__) < (__mat__)->nelems; (__ite__)++)

#define _MAT_FOREACH_ELEM_UPPER(__mat__, __itr__, __itc__)                    \
  for ((__itr__) = 0; (__itr__) < (__mat__)->nrows; (__itr__)++)              \
    for ((__itc__) = (__itr__); (__itc__) < (__mat__)->ncols; (__itc__)++)

#define _POLYRING_FOREACH_P(__ring__, __it__)                                 \
  for ((__it__) = 0; (__it__) < (__ring__)->nmoduli; (__it__)++)

static inline int
_neg2sign (limb_t neg)
{
  return (int)1 - (((int)neg) << 1);
}

static inline limb_t
_sign2neg (int sign)
{
  return ((limb_t)(1 - sign)) >> 1;
}

static inline limb_t
_i642neg (int64_t si)
{
  return ((limb_t)1 & (limb_t)(si >> ((sizeof (int64_t) << 3) - 1)));
}

static inline int
_i642sign (int64_t si)
{
  return _neg2sign (_i642neg (si));
}

static inline size_t
_sizeof_int_data (unsigned int nlimbs)
{
  return nlimbs * sizeof (limb_t);
}

static inline size_t
_sizeof_int (unsigned int nlimbs)
{
  return _sizeof_int_data (nlimbs) + sizeof (int_t);
}

static inline size_t
_sizeof_intvec_data (unsigned int nelems, unsigned int nlimbs)
{
  return nelems * _sizeof_int_data (nlimbs) + nelems * sizeof (int_t);
}

static inline size_t
_sizeof_intmat_data (unsigned int nrows, unsigned int ncols,
                     unsigned int nlimbs)
{
  return nrows * ncols * _sizeof_int_data (nlimbs)
         + nrows * ncols * sizeof (int_t);
}

static inline size_t
_sizeof_intmat (unsigned int nrows, unsigned int ncols, unsigned int nlimbs)
{
  return _sizeof_intmat_data (nrows, ncols, nlimbs) + sizeof (intmat_t);
}

static inline size_t
_sizeof_crtrep_data (polyring_srcptr ring)
{
  return sizeof (crtcoeff_t) * ring->d * ring->nmoduli;
}

static inline size_t
_sizeof_poly_data (polyring_srcptr ring)
{
  return /*_sizeof_crtrep_data (ring)
         + XXX*/
      _sizeof_intvec_data (ring->d, ring->q->nlimbs) + sizeof (intvec_t);
}

static inline size_t
_sizeof_poly (polyring_srcptr ring)
{
  return _sizeof_poly_data (ring) + sizeof (poly_t);
}

static inline size_t
_sizeof_polyvec_data (polyring_srcptr ring, unsigned int nelems)
{
  return nelems * _sizeof_poly_data (ring) + nelems * sizeof (poly_t);
}

static inline size_t
_sizeof_polyvec (polyring_srcptr ring, unsigned int nelems)
{
  return _sizeof_polyvec_data (ring, nelems) + sizeof (polyvec_t);
}

static inline size_t
_sizeof_polymat_data (polyring_srcptr ring, unsigned int nrows,
                      unsigned int ncols)
{
  return nrows * ncols * _sizeof_poly_data (ring)
         + nrows * ncols * sizeof (poly_t);
}

static inline size_t
_sizeof_polymat (polyring_srcptr ring, unsigned int nrows, unsigned int ncols)
{
  return _sizeof_polymat_data (ring, nrows, ncols + sizeof (polymat_t));
}

static inline void
_int_init (int_t r, unsigned int nlimbs, void *mem)
{
  r->limbs = (limb_t *)mem;
  r->nlimbs = nlimbs;
  r->neg = 0;
}

static inline void
_intvec_init (intvec_t r, unsigned int nelems, unsigned int nlimbs, void *mem)
{
  int_ptr elem;
  unsigned int i;

  r->bytes = mem;
  r->nbytes = nelems * _sizeof_int (nlimbs);

  r->elems = (int_ptr)((uint8_t *)mem + nelems * _sizeof_int_data (nlimbs));
  r->nlimbs = nlimbs;
  r->nelems = nelems;
  r->stride_elems = 1;

  _VEC_FOREACH_ELEM (r, i)
  {
    elem = intvec_get_elem (r, i);
    _int_init (elem, nlimbs, (uint8_t *)mem + i * _sizeof_int_data (nlimbs));
  }
}

static inline void
_intmat_init (intmat_t r, unsigned int nrows, unsigned int ncols,
              unsigned int nlimbs, void *mem)
{
  unsigned int i, j;
  int_ptr elem;

  r->bytes = mem;
  r->nbytes = nrows * ncols * _sizeof_int (nlimbs);

  r->cpr = ncols;

  r->elems
      = (int_ptr)((uint8_t *)mem + nrows * ncols * _sizeof_int_data (nlimbs));
  r->nlimbs = nlimbs;

  r->nrows = nrows;
  r->stride_row = 1;

  r->ncols = ncols;
  r->stride_col = 1;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    elem = intmat_get_elem (r, i, j);
    _int_init (elem, nlimbs,
               (uint8_t *)mem + ((i * ncols) + j) * _sizeof_int_data (nlimbs));
  }
}

static inline void
_poly_init (poly_t r, polyring_srcptr ring, void *mem)
{
  r->ring = ring;
  r->crtrep = NULL;
  r->crt = 0;
  r->mem = NULL;
  r->flags = 0;
  r->coeffs = (intvec_ptr)((uint8_t *)mem /*+ _sizeof_crtrep_data (ring)XXX*/
                           + _sizeof_intvec_data (ring->d, ring->q->nlimbs));
  _intvec_init (r->coeffs, ring->d, ring->q->nlimbs,
                (uint8_t *)mem /*XXX+ _sizeof_crtrep_data (ring)*/);
}

static inline void
_polyvec_init (polyvec_t r, polyring_srcptr ring, unsigned int nelems,
               void *mem)
{
  poly_ptr elem;
  unsigned int i;

  r->ring = ring;
  r->nelems = nelems;
  r->elems = (poly_ptr)((uint8_t *)mem + nelems * _sizeof_poly_data (ring));
  r->stride_elems = 1;
  r->mem = NULL;
  r->flags = 0;

  _VEC_FOREACH_ELEM (r, i)
  {
    elem = polyvec_get_elem (r, i);
    _poly_init (elem, ring, (uint8_t *)mem + i * _sizeof_poly_data (ring));
  }
}

static inline void
_polymat_init (polymat_t r, polyring_srcptr ring, unsigned int nrows,
               unsigned int ncols, void *mem)
{
  unsigned int i, j;
  poly_ptr elem;

  r->ring = ring;
  r->cpr = ncols;

  r->elems
      = (poly_ptr)((uint8_t *)mem + nrows * ncols * _sizeof_poly_data (ring));

  r->nrows = nrows;
  r->stride_row = 1;

  r->ncols = ncols;
  r->stride_col = 1;

  r->mem = NULL;
  r->flags = 0;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    elem = polymat_get_elem (r, i, j);
    _poly_init (elem, ring,
                (uint8_t *)mem + ((i * ncols) + j) * _sizeof_poly_data (ring));
  }
}

static inline void
_tocrt (poly_t r)
{
  if (!r->crt)
    {
      poly_tocrt (r);
      r->crt = 1;
    }
}

static inline void
_fromcrt (poly_t r)
{
  if (r->crt)
    {
      poly_fromcrt (r);
      r->crt = 0;
    }
}

static inline int
_to_same_dom (poly_t a, poly_t b, int crt)
{
  if (a->crt ^ b->crt)
    {
      if (crt)
        {
          _tocrt (a);
          _tocrt (b);
        }
      else
        {
          _fromcrt (a);
          _fromcrt (b);
        }
      return crt;
    }
  return a->crt;
}

static inline crtcoeff_t *
_get_crtcoeff (crtcoeff_t *crtrep, unsigned int pi, unsigned int coeff,
               unsigned int deg)
{
  ASSERT_ERR (coeff < deg);

  return crtrep + pi * deg + coeff;
}

static inline intvec_srcptr
_get_coeffvec_src (const poly_t poly)
{
  return poly->coeffs;
}

static inline intvec_ptr
_get_coeffvec (poly_t poly)
{
  return poly->coeffs;
}

#ifndef _OS_IOS
#include <immintrin.h>
#include <x86intrin.h>
#endif

static inline void limbs_cpy (limb_t *a, const limb_t *b, unsigned int n);
static inline void limbs_set (limb_t *a, limb_t b, unsigned int n);

static inline limb_t limb_eq_ct (const limb_t a, const limb_t b);

static inline limb_t limbs_eq_zero_ct (const limb_t *a, unsigned int n);

static inline limb_t limbs_eq_ct (const limb_t *a, const limb_t *b,
                                  unsigned int n);
static inline limb_t limbs_lt_ct (const limb_t *a, const limb_t *b,
                                  unsigned int n);
static inline limb_t limbs_le_ct (const limb_t *a, const limb_t *b,
                                  unsigned int n);
static inline limb_t limbs_gt_ct (const limb_t *a, const limb_t *b,
                                  unsigned int n);
static inline limb_t limbs_ge_ct (const limb_t *a, const limb_t *b,
                                  unsigned int n);
static inline limb_t limbs_add (limb_t *r, const limb_t *a, const limb_t *b,
                                uint8_t c, unsigned int nlimbs);
static inline limb_t limbs_sub (limb_t *r, const limb_t *a, const limb_t *b,
                                uint8_t c, unsigned int nlimbs);

static inline void limbs_cnd_select (limb_t *r, limb_t *a, limb_t *b,
                                     unsigned int nlimbs, limb_t c);
static inline void limbs_to_twoscom (limb_t *out, const limb_t *in,
                                     unsigned int nlimbs, limb_t neg);
static inline limb_t limbs_from_twoscom (limb_t *limbs, unsigned int nlimbs);
static inline void limbs_to_twoscom_ct (limb_t *limbs, unsigned int nlimbs,
                                        limb_t neg);
static inline limb_t limbs_from_twoscom_ct (limb_t *limbs,
                                            unsigned int nlimbs);

static inline unsigned char
_addcarry_u64_ (unsigned char c, unsigned long long x, unsigned long long y,
                unsigned long long *p)
{
#ifdef _OS_IOS
  unsigned long long cout;

  *p = __builtin_addcll (x, y, c, &cout);
  return cout;
#else
  return _addcarry_u64 (c, x, y, p);
#endif
}

static inline unsigned char
_subborrow_u64_ (unsigned char c, unsigned long long x, unsigned long long y,
                 unsigned long long *p)
{
#ifdef _OS_IOS
  unsigned long long cout;

  *p = __builtin_subcll (x, y, c, &cout);
  return cout;
#else
  return _subborrow_u64 (c, x, y, p);
#endif
}

#define NBITS_LIMB ((limb_t)(sizeof (limb_t) << 3))

static inline void
limbs_cpy (limb_t *a, const limb_t *b, unsigned int n)
{
  unsigned int i;

  for (i = 0; i < n; i++)
    a[i] = b[i];
}

static inline void
limbs_set (limb_t *a, limb_t b, unsigned int n)
{
  unsigned int i;

  for (i = 0; i < n; i++)
    a[i] = b;
}

static inline limb_t
limb_eq_ct (const limb_t a, const limb_t b)
{
  limb_t t;

  t = a ^ b;
  return (limb_t)1 ^ ((t | -t) >> (NBITS_LIMB - 1));
}

static inline limb_t
limbs_eq_zero_ct (const limb_t *a, unsigned int n)
{
  unsigned int i;
  limb_t r;

  r = 0;
  for (i = 0; i < n; i++)
    r |= a[i];
  return limb_eq_ct (r, 0);
}

static inline limb_t
limbs_eq_ct (const limb_t *a, const limb_t *b, unsigned int n)
{
  unsigned int i;
  limb_t r;

  r = 0;
  for (i = 0; i < n; i++)
    r |= (a[i] ^ b[i]);
  return limb_eq_ct (r, 0);
}

static inline limb_t
limbs_lt (const limb_t *a, const limb_t *b, unsigned int n)
{
  unsigned int i;

  for (i = n; i > 0; i--)
    {
      if (a[i - 1] != b[i - 1])
        {
          if (a[i - 1] < b[i - 1])
            return 1;
          else
            return 0;
        }
    }

  return 0; /* equality */
}

static inline limb_t
limbs_lt_ct (const limb_t *a, const limb_t *b, unsigned int n)
{
  limb_t carry, tmp[n];

  carry = limbs_sub (tmp, a, b, 0, n);
  return carry;
}

static inline limb_t
limbs_le_ct (const limb_t *a, const limb_t *b, unsigned int n)
{
  limb_t carry, tmp[n];

  carry = limbs_sub (tmp, a, b, 0, n);
  return carry | limbs_eq_zero_ct (tmp, n);
}

static inline limb_t
limbs_gt_ct (const limb_t *a, const limb_t *b, unsigned int n)
{
  limb_t carry, tmp[n];

  carry = limbs_sub (tmp, b, a, 0, n);
  return carry;
}

static inline limb_t
limbs_ge_ct (const limb_t *a, const limb_t *b, unsigned int n)
{
  limb_t carry, tmp[n];

  carry = limbs_sub (tmp, b, a, 0, n);
  return carry | limbs_eq_zero_ct (tmp, n);
}

static inline limb_t
limbs_add (limb_t *r, const limb_t *a, const limb_t *b, uint8_t c,
           unsigned int nlimbs)
{
  unsigned int i;

  for (i = 0; i < nlimbs; i++)
    c = _addcarry_u64_ (c, a[i], b[i], (unsigned long long *)&r[i]);

  return c;
}

static inline limb_t
limbs_sub (limb_t *r, const limb_t *a, const limb_t *b, uint8_t c,
           unsigned int nlimbs)
{
  unsigned int i;

  for (i = 0; i < nlimbs; i++)
    c = _subborrow_u64_ (c, a[i], b[i], (unsigned long long *)&r[i]);

  return c;
}

static inline void
limbs_cnd_select (limb_t *r, limb_t *a, limb_t *b, unsigned int nlimbs,
                  limb_t c)
{
  const limb_t mask1 = (limb_t)(-((long long)c)); /* c == 1 : mask1 == ~0 */
  const limb_t mask2 = ~mask1;                    /* c == 1 : mask2 == 0 */
  unsigned int i;

  for (i = 0; i < nlimbs; i++)
    r[i] = a[i] ^ b[i] ^ (a[i] & mask1) ^ (b[i] & mask2);
}

static inline void
limbs_to_twoscom (limb_t *out, const limb_t *in, unsigned int nlimbs,
                  limb_t neg)
{
  unsigned int i;

  if (neg)
    {
      const limb_t mask = ~(limb_t)0;
      unsigned char c = 1;

      for (i = 0; i < nlimbs; i++)
        {
          out[i] = in[i] ^ mask;
          c = _addcarry_u64_ (c, out[i], 0, (unsigned long long *)&out[i]);
        }
    }
  else
    {
      for (i = 0; i < nlimbs; i++)
        {
          out[i] = in[i];
        }
    }
}

static inline limb_t
limbs_from_twoscom (limb_t *limbs, unsigned int nlimbs)
{
  limb_t neg;

  neg = (limbs[nlimbs - 1] >> (NBITS_LIMB - 1));
  limbs_to_twoscom (limbs, limbs, nlimbs, neg);
  return neg;
}

static inline void
limbs_to_twoscom_ct (limb_t *limbs, unsigned int nlimbs, limb_t neg)
{
  limb_t scratch[mpn_sec_add_1_itch (nlimbs)];
  limb_t comp[nlimbs];

  mpn_com (comp, limbs, nlimbs);
  mpn_sec_add_1 (comp, comp, nlimbs, 1, scratch);
  mpn_cnd_swap (neg, limbs, comp, nlimbs);
}

static inline limb_t
limbs_from_twoscom_ct (limb_t *limbs, unsigned int nlimbs)
{
  limb_t neg;

  neg = limbs[nlimbs - 1] >> (NBITS_LIMB - 1);
  limbs_to_twoscom_ct (limbs, nlimbs, neg);
  return neg;
}

/********************************************************************
 * 3.3 Implementations of API inline functions
 */

static inline unsigned int
int_get_nlimbs (const int_t a)
{
  return a->nlimbs;
}

static inline void
int_neg_self (int_t r)
{
  r->neg ^= 1;
}

static inline void
intvec_neg_self (intvec_t r)
{
  unsigned int i;
  int_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = intvec_get_elem (r, i);
    int_neg_self (rptr);
  }
}

static inline void
intvec_neg (intvec_t r, intvec_srcptr b)
{
  unsigned int i;
  int_ptr rptr, bptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = intvec_get_elem (r, i);
    bptr = intvec_get_elem (b, i);
    int_neg (rptr, bptr);
  }
}

static inline void
int_set_zero (int_t r)
{
  int_set_i64 (r, 0);
}

static inline void
int_set_one (int_t r)
{
  int_set_i64 (r, 1);
}

static inline void
int_set (int_t r, const int_t a)
{
  unsigned int i, nlimbs;

  for (i = r->nlimbs - 1; i >= a->nlimbs; i--)
    r->limbs[i] = 0;

  nlimbs = MIN (a->nlimbs, r->nlimbs);

  limbs_cpy (r->limbs, a->limbs, nlimbs);
  r->neg = a->neg;
}

static inline void
int_set_i64 (int_t r, int64_t a)
{
  r->neg = _i642neg (a);
  r->limbs[0] = _i642sign (a) * a;
  limbs_set (r->limbs + 1, 0, r->nlimbs - 1);
}

static inline int64_t
int_get_i64 (const int_t r)
{
  return _neg2sign (r->neg) * r->limbs[0];
}

static inline void
int_neg (int_t r, const int_t a)
{
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  int_set (r, a);
  r->neg ^= 1;
}

static inline void
int_abs (int_t r, const int_t a)
{
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  int_set (r, a);
  r->neg = 0;
}

/* also return 1 for negative zero */
static inline int
int_sgn (const int_t a)
{
  const limb_t b = limbs_eq_zero_ct (a->limbs, a->nlimbs);

  return ((int)-1 + (b << 1)) & (_neg2sign (a->neg));
}

static inline void
int_mul_sgn_self (int_t r, int sgn)
{
  ASSERT_ERR (sgn == 1 || sgn == -1);

  r->neg = _sign2neg (int_sgn (r) * sgn);
}

static inline void
int_mul1 (int_t r, const int_t a, crtcoeff_t b)
{
#if 1
  crtcoeff_t c = 0;
  crtcoeff_dbl_t prod;
  unsigned int i;

  ASSERT_ERR (r->nlimbs == a->nlimbs + 1);

  r->neg = a->neg ^ (((uint64_t)b) >> 63); // get sign bit;
  if (b < 0)
    b = -b;

  for (i = 0; i < a->nlimbs; i++)
    {
      prod = (crtcoeff_dbl_t)a->limbs[i] * b + c;
      r->limbs[i] = prod & 0xffffffffffffffffULL;
      c = prod >> 64;
    }
  r->limbs[a->nlimbs] = c;
#else
  ASSERT_ERR (r->nlimbs == a->nlimbs + 1);

  r->neg = a->neg ^ (((uint64_t)b) >> 63); // get sign bit;
  if (b < 0)
    b = -b;

  r->limbs[a->nlimbs] = mpn_mul_1 (r->limbs, a->limbs, a->nlimbs, b);
#endif
}

static inline int
int_eqzero (const int_t a)
{
  return limbs_eq_zero_ct (a->limbs, a->nlimbs);
}

static inline int
int_abseq (const int_t a, const int_t b)
{
  ASSERT_ERR (a->nlimbs == b->nlimbs);

  return limbs_eq_ct (a->limbs, b->limbs, a->nlimbs);
}

static inline int
int_abslt (const int_t a, const int_t b)
{
  ASSERT_ERR (a->nlimbs == b->nlimbs);

  return limbs_lt_ct (a->limbs, b->limbs, a->nlimbs);
}

static inline int
int_absle (const int_t a, const int_t b)
{
  ASSERT_ERR (a->nlimbs == b->nlimbs);

  return limbs_le_ct (a->limbs, b->limbs, a->nlimbs);
}

static inline int
int_absgt (const int_t a, const int_t b)
{
  ASSERT_ERR (a->nlimbs == b->nlimbs);

  return limbs_gt_ct (a->limbs, b->limbs, a->nlimbs);
}

static inline int
int_absge (const int_t a, const int_t b)
{
  ASSERT_ERR (a->nlimbs == b->nlimbs);

  return limbs_ge_ct (a->limbs, b->limbs, a->nlimbs);
}

static inline int
int_eq (const int_t a, const int_t b)
{
  limb_t an, bn, eq;

  ASSERT_ERR (a->nlimbs == b->nlimbs);

  an = a->neg & (1 ^ limbs_eq_zero_ct (a->limbs, a->nlimbs));
  bn = b->neg & (1 ^ limbs_eq_zero_ct (b->limbs, b->nlimbs));
  eq = limbs_eq_ct (a->limbs, b->limbs, a->nlimbs);
  return (1 ^ an ^ bn) & eq;
}

static inline int
int_lt (const int_t a, const int_t b)
{
  limb_t an, bn, eq, lt;

  ASSERT_ERR (a->nlimbs == b->nlimbs);

  /* make negative zeros positive. */
  an = a->neg & (1 ^ limbs_eq_zero_ct (a->limbs, a->nlimbs));
  bn = b->neg & (1 ^ limbs_eq_zero_ct (b->limbs, b->nlimbs));
  eq = limbs_eq_ct (a->limbs, b->limbs, a->nlimbs);
  lt = limbs_lt_ct (a->limbs, b->limbs, a->nlimbs);
  return ((an ^ bn) & an) | (an & bn & (1 ^ lt) & (1 ^ eq))
         | ((1 ^ an) & (1 ^ bn) & lt);
}

static inline int
int_le (const int_t a, const int_t b)
{
  limb_t an, bn, eq, lt;

  ASSERT_ERR (a->nlimbs == b->nlimbs);

  /* make negative zeros positive. */
  an = a->neg & (1 ^ limbs_eq_zero_ct (a->limbs, a->nlimbs));
  bn = b->neg & (1 ^ limbs_eq_zero_ct (b->limbs, b->nlimbs));
  eq = limbs_eq_ct (a->limbs, b->limbs, a->nlimbs);
  lt = limbs_lt_ct (a->limbs, b->limbs, a->nlimbs);
  return ((an ^ bn) & an) | (an & bn & (1 ^ lt))
         | ((1 ^ an) & (1 ^ bn) & (lt | eq));
}

static inline int
int_gt (const int_t a, const int_t b)
{
  limb_t an, bn, eq, gt;

  ASSERT_ERR (a->nlimbs == b->nlimbs);

  /* make negative zeros positive. */
  an = a->neg & (1 ^ limbs_eq_zero_ct (a->limbs, a->nlimbs));
  bn = b->neg & (1 ^ limbs_eq_zero_ct (b->limbs, b->nlimbs));
  eq = limbs_eq_ct (a->limbs, b->limbs, a->nlimbs);
  gt = limbs_gt_ct (a->limbs, b->limbs, a->nlimbs);
  return ((an ^ bn) & (1 ^ an)) | (an & bn & (1 ^ gt) & (1 ^ eq))
         | ((1 ^ an) & (1 ^ bn) & gt);
}

static int
int_ge (const int_t a, const int_t b)
{
  limb_t an, bn, eq, gt;

  ASSERT_ERR (a->nlimbs == b->nlimbs);

  /* make negative zeros positive. */
  an = a->neg & (1 ^ limbs_eq_zero_ct (a->limbs, a->nlimbs));
  bn = b->neg & (1 ^ limbs_eq_zero_ct (b->limbs, b->nlimbs));
  eq = limbs_eq_ct (a->limbs, b->limbs, a->nlimbs);
  gt = limbs_gt_ct (a->limbs, b->limbs, a->nlimbs);
  return ((an ^ bn) & (1 ^ an)) | (an & bn & (1 ^ gt))
         | ((1 ^ an) & (1 ^ bn) & (gt | eq));
}

static inline void
int_rshift (int_t r, const int_t a, unsigned int n)
{
  unsigned int nlimbs, nbits, i;

  nlimbs = n / NBITS_LIMB;
  nbits = n - nlimbs * NBITS_LIMB;

  if (UNLIKELY (nlimbs >= a->nlimbs))
    {
      nlimbs = a->nlimbs;
      nbits = 0;
    }

  for (i = 0; i < MIN (r->nlimbs, a->nlimbs - nlimbs); i++)
    r->limbs[i] = a->limbs[i + nlimbs];
  for (; i < r->nlimbs; i++)
    r->limbs[i] = 0;

  if (nbits > 0)
    mpn_rshift (r->limbs, r->limbs, r->nlimbs, nbits);

  r->neg = a->neg;
}

static inline void
int_lshift (int_t r, const int_t a, unsigned int n)
{
  unsigned int nlimbs, nbits;
  long i;

  nlimbs = n / NBITS_LIMB;
  nbits = n - nlimbs * NBITS_LIMB;

  for (i = r->nlimbs - 1; i >= a->nlimbs + nlimbs; i--)
    r->limbs[i] = 0;
  for (; i >= nlimbs; i--)
    r->limbs[i] = a->limbs[i - nlimbs];
  for (; i >= 0; i--)
    r->limbs[i] = 0;

  if (nbits > 0)
    mpn_lshift (r->limbs, r->limbs, r->nlimbs, nbits);

  r->neg = a->neg;
}

#if 0
static inline void
int_add (int_t r, const int_t a, const int_t b)
{
  limb_t ta[r->nlimbs];
  limb_t tb[r->nlimbs];
  unsigned char c = 0;

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  limbs_to_twoscom (ta, a->limbs, r->nlimbs, a->neg);
  limbs_to_twoscom (tb, b->limbs, r->nlimbs, b->neg);

  limbs_add (r->limbs, ta, tb, c, r->nlimbs);

  r->neg = limbs_from_twoscom (r->limbs, r->nlimbs);
}
#else
static inline void
int_add (int_t r, const int_t a, const int_t b)
{
  limb_t c;

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  if (a->neg == b->neg)
    {
      limbs_add (r->limbs, a->limbs, b->limbs, 0, r->nlimbs);
      r->neg = a->neg;
    }
  else
    {
      c = limbs_sub (r->limbs, a->limbs, b->limbs, 0, r->nlimbs);
      if (c)
        {
          limbs_from_twoscom (r->limbs, r->nlimbs);
          r->neg = b->neg;
        }
      else
        {
          r->neg = a->neg;
        }
    }
}
#endif

static inline void
int_add_ct (int_t r, const int_t a, const int_t b)
{
  limb_t _a[a->nlimbs], _b[b->nlimbs];

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  mpn_copyi (_a, a->limbs, a->nlimbs);
  mpn_copyi (_b, b->limbs, b->nlimbs);

  limbs_to_twoscom_ct (_a, a->nlimbs, a->neg);
  limbs_to_twoscom_ct (_b, b->nlimbs, b->neg);

  limbs_add (r->limbs, _a, _b, 0, r->nlimbs);
  r->neg = limbs_from_twoscom_ct (r->limbs, r->nlimbs);
}

#if 0
static inline void
int_sub (int_t r, const int_t a, const int_t b)
{
  limb_t ta[r->nlimbs];
  limb_t tb[r->nlimbs];
  unsigned char c = 0;

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  limbs_to_twoscom (ta, a->limbs, r->nlimbs, a->neg);
  limbs_to_twoscom (tb, b->limbs, r->nlimbs, b->neg);

  limbs_sub (r->limbs, ta, tb, c, r->nlimbs);

  r->neg = limbs_from_twoscom (r->limbs, r->nlimbs);
}
#else
static inline void
int_sub (int_t r, const int_t a, const int_t b)
{
  limb_t c;

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  if (a->neg != b->neg)
    {
      limbs_add (r->limbs, a->limbs, b->limbs, 0, r->nlimbs);
      r->neg = a->neg;
    }
  else
    {
      c = limbs_sub (r->limbs, a->limbs, b->limbs, 0, r->nlimbs);
      if (c)
        {
          limbs_from_twoscom (r->limbs, r->nlimbs);
          r->neg = !b->neg;
        }
      else
        {
          r->neg = a->neg;
        }
    }
}
#endif

static inline void
int_sub_ct (int_t r, const int_t a, const int_t b)
{
  limb_t _a[a->nlimbs], _b[b->nlimbs];

  ASSERT_ERR (a->nlimbs == b->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  mpn_copyi (_a, a->limbs, a->nlimbs);
  mpn_copyi (_b, b->limbs, b->nlimbs);

  limbs_to_twoscom_ct (_a, a->nlimbs, a->neg);
  limbs_to_twoscom_ct (_b, b->nlimbs, 1 ^ b->neg);

  limbs_add (r->limbs, _a, _b, 0, r->nlimbs);
  r->neg = limbs_from_twoscom (r->limbs, r->nlimbs);
}

/* [-(m-1),...,(m-1)] -> [-(m-1)/2,...,(m-1)/2] */
static inline void
int_redc (int_t r, const int_t a, const int_t m)
{
  limb_t tmp[a->nlimbs];
  limb_t b;

  ASSERT_ERR (a->nlimbs == m->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  limbs_sub (tmp, m->limbs, a->limbs, 0, m->nlimbs);

  b = limbs_lt (tmp, a->limbs, m->nlimbs);
  if (b)
    {
      limbs_cpy (r->limbs, tmp, m->nlimbs);
    }
  else
    {
      limbs_cpy (r->limbs, a->limbs, m->nlimbs);
    }
  r->neg = b ^ a->neg;
}

/* [-(m-1),...,(m-1)] -> [-(m-1)/2,...,(m-1)/2] */
static inline void
int_redc_ct (int_t r, const int_t a, const int_t m)
{
  limb_t tmp[a->nlimbs];
  limb_t b;

  ASSERT_ERR (a->nlimbs == m->nlimbs);
  ASSERT_ERR (r->nlimbs == a->nlimbs);

  limbs_cpy (r->limbs, a->limbs, m->nlimbs);
  limbs_sub (tmp, m->limbs, a->limbs, 0, m->nlimbs);

  b = limbs_lt_ct (tmp, r->limbs, m->nlimbs);
  limbs_cnd_select (r->limbs, r->limbs, tmp, m->nlimbs, b);
  r->neg = b ^ a->neg;
}

// XXX
/* result in [-(m-1),...,m-1] */
static inline crtcoeff_t
int_mod_XXX (const int_t a, crtcoeff_t m)
{
  limb_t d1, d2, r;
  int k;

  r = 0;
  for (k = a->nlimbs - 1; k >= 0; k--)
    {
      d1 = r;
      d2 = a->limbs[k];
      r = (((crtcoeff_dbl_t)d1 << CRTCOEFF_NBITS) + d2) % m; // XXX
    }

  return a->neg ? -r : r;
}
// XXX
// XXX
/* result in [-(m-1),...,m-1] */
static inline uint64_t
int_mod_XXX_hexl (const int_t a, crtcoeff_t m)
{
  limb_t d1, d2, r;
  int k;

  r = 0;
  for (k = a->nlimbs - 1; k >= 0; k--)
    {
      d1 = r;
      d2 = a->limbs[k];
      r = (((crtcoeff_dbl_t)d1 << CRTCOEFF_NBITS) + d2) % m; // XXX
    }

  return a->neg ? m - r : r;
}

static inline unsigned int
intvec_get_nlimbs (const intvec_t a)
{
  return a->nlimbs;
}

static inline unsigned int
intvec_get_nelems (const intvec_t r)
{
  return r->nelems;
}

static inline void
intvec_set_zero (intvec_t r)
{
  unsigned int i;
  int_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = intvec_get_elem (r, i);
    int_set_zero (ri);
  }
}

static inline void
intvec_set_ones (intvec_t r)
{
  unsigned int i;
  int_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = intvec_get_elem (r, i);
    int_set_one (ri);
  }
}

static inline void
intvec_set_one (intvec_t r, unsigned int idx)
{
  unsigned int i;
  int_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = intvec_get_elem (r, i);

    if (i == idx)
      int_set_one (ri);
    else
      int_set_zero (ri);
  }
}

static inline int_ptr
intvec_get_elem (const intvec_t a, unsigned int elem)
{
  ASSERT_ERR (elem < a->nelems);

  return &(a->elems[elem * a->stride_elems]);
}

static inline int_srcptr
intvec_get_elem_src (const intvec_t a, unsigned int elem)
{
  return intvec_get_elem (a, elem);
}

static inline void
intvec_set_elem (intvec_t a, unsigned int idx, const int_t elem)
{
  int_ptr ptr;

  ASSERT_ERR (idx < a->nelems);

  ptr = intvec_get_elem (a, idx);
  int_set (ptr, elem);
}

static inline int64_t
intvec_get_elem_i64 (const intvec_t a, unsigned int elem)
{
  return int_get_i64 (intvec_get_elem_src (a, elem));
}

static inline void
intvec_set_elem_i64 (intvec_t a, unsigned int elem, int64_t val)
{
  int_ptr ptr;

  ptr = intvec_get_elem (a, elem);
  int_set_i64 (ptr, val);
}

static inline void
intvec_set (intvec_t r, const intvec_t a)
{
  INT_T (zero, 1);
  unsigned int i;
  int_srcptr ai;

  ASSERT_ERR (r->nelems >= a->nelems);

  int_set_i64 (zero, 0);

  for (i = r->nelems - 1; i >= a->nelems; i--)
    intvec_set_elem (r, i, zero);

  _VEC_FOREACH_ELEM (a, i)
  {
    ai = intvec_get_elem_src (a, i);
    intvec_set_elem (r, i, ai);
  }
}

static inline void
intvec_set_i64 (intvec_t r, const int64_t *a)
{
  unsigned int i;
  int_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = intvec_get_elem (r, i);
    int_set_i64 (rptr, a[i]);
  }
}

static inline void
intvec_set_i32 (intvec_t r, const int32_t *a)
{
  unsigned int i;
  int_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = intvec_get_elem (r, i);
    int_set_i64 (rptr, a[i]);
  }
}

static inline void
intvec_set_i16 (intvec_t r, const int16_t *a)
{
  unsigned int i;
  int_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = intvec_get_elem (r, i);
    int_set_i64 (rptr, a[i]);
  }
}

static inline void
intvec_set_i8 (intvec_t r, const int8_t *a)
{
  unsigned int i;
  int_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = intvec_get_elem (r, i);
    int_set_i64 (rptr, a[i]);
  }
}

static inline void
intvec_get_i8 (int8_t *r, const intvec_t a)
{
  unsigned int i;
  int64_t tmp;

  _VEC_FOREACH_ELEM (a, i)
  {
    tmp = intvec_get_elem_i64 (a, i);
    ASSERT_ERR (tmp >= INT8_MIN);
    ASSERT_ERR (tmp <= INT8_MAX);

    r[i] = (int8_t)tmp;
  }
}

static inline void
intvec_get_i16 (int16_t *r, const intvec_t a)
{
  unsigned int i;
  int64_t tmp;

  _VEC_FOREACH_ELEM (a, i)
  {
    tmp = intvec_get_elem_i64 (a, i);
    ASSERT_ERR (tmp >= INT16_MIN);
    ASSERT_ERR (tmp <= INT16_MAX);

    r[i] = (int16_t)tmp;
  }
}

static inline void
intvec_get_i32 (int32_t *r, const intvec_t a)
{
  unsigned int i;
  int64_t tmp;

  _VEC_FOREACH_ELEM (a, i)
  {
    tmp = intvec_get_elem_i64 (a, i);
    ASSERT_ERR (tmp >= INT32_MIN);
    ASSERT_ERR (tmp <= INT32_MAX);

    r[i] = (int32_t)tmp;
  }
}

static inline void
intvec_get_i64 (int64_t *r, const intvec_t a)
{
  unsigned int i;
  int64_t tmp;

  _VEC_FOREACH_ELEM (a, i)
  {
    tmp = intvec_get_elem_i64 (a, i);
    r[i] = (int64_t)tmp;
  }
}

static inline unsigned int
intmat_get_nlimbs (const intmat_t a)
{
  return a->nlimbs;
}

static inline unsigned int
intmat_get_nrows (const intmat_t mat)
{
  return mat->nrows;
}

static inline unsigned int
intmat_get_ncols (const intmat_t mat)
{
  return mat->ncols;
}

static inline void
intmat_set_zero (intmat_t r)
{
  unsigned int i, j;
  int_ptr ri;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    ri = intmat_get_elem (r, i, j);
    int_set_zero (ri);
  }
}

static inline void
intmat_set_one (intmat_t r)
{
  intvec_t diag;
  unsigned int i, j;
  int_ptr ri;

  intmat_get_diag (diag, r, 0);
  intvec_set_ones (diag);

  _MAT_FOREACH_ELEM (r, i, j)
  {
    if (i != j)
      {
        ri = intmat_get_elem (r, i, j);
        int_set_zero (ri);
      }
  }
}

static inline int_ptr
intmat_get_elem (const intmat_t a, unsigned int row, unsigned int col)
{
  ASSERT_ERR (row < a->nrows);
  ASSERT_ERR (col < a->ncols);

  return &(a->elems[row * a->stride_row * a->cpr + col * a->stride_col]);
}

static inline int_srcptr
intmat_get_elem_src (const intmat_t a, unsigned int row, unsigned int col)
{
  return intmat_get_elem (a, row, col);
}

static inline int64_t
intmat_get_elem_i64 (const intmat_t a, unsigned int row, unsigned int col)
{
  ASSERT_ERR (row < a->nrows);
  ASSERT_ERR (col < a->ncols);

  return int_get_i64 (intmat_get_elem_src (a, row, col));
}

static inline void
intmat_set_elem (intmat_t a, unsigned int row, unsigned int col,
                 const int_t elem)
{
  int_ptr ptr;

  ASSERT_ERR (row < a->nrows);
  ASSERT_ERR (col < a->ncols);

  ptr = intmat_get_elem (a, row, col);
  int_set (ptr, elem);
}

static inline void
intmat_set_elem_i64 (intmat_t a, unsigned int row, unsigned int col,
                     int64_t elem)
{
  int_ptr ptr;

  ASSERT_ERR (row < a->nrows);
  ASSERT_ERR (col < a->ncols);

  ptr = intmat_get_elem (a, row, col);
  int_set_i64 (ptr, elem);
}

static inline void
intmat_get_row (intvec_t subvec, const intmat_t mat, unsigned int row)
{
  ASSERT_ERR (row < mat->nrows);

  subvec->bytes = mat->bytes;
  subvec->nbytes = mat->nbytes;

  subvec->elems = intmat_get_elem (mat, row, 0);
  subvec->nlimbs = mat->nlimbs;

  subvec->nelems = mat->ncols;
  subvec->stride_elems = mat->stride_col;
}

static inline void
intmat_set_row (intmat_t mat, const intvec_t vec, unsigned int row)
{
  intvec_t tmp;

  intmat_get_row (tmp, mat, row);
  intvec_set (tmp, vec);
}

static inline void
intmat_get_col (intvec_t subvec, const intmat_t mat, unsigned int col)
{
  ASSERT_ERR (col < mat->ncols);

  subvec->bytes = mat->bytes;
  subvec->nbytes = mat->nbytes;

  subvec->elems = intmat_get_elem (mat, 0, col);
  subvec->nlimbs = mat->nlimbs;

  subvec->nelems = mat->nrows;
  subvec->stride_elems = mat->stride_row * mat->cpr;
}

static inline void
intmat_set_col (intmat_t mat, const intvec_t vec, unsigned int col)
{
  intvec_t tmp;

  intmat_get_col (tmp, mat, col);
  intvec_set (tmp, vec);
}

static inline void
intmat_get_diag (intvec_t subvec, const intmat_t mat, int diag)
{
  unsigned int row = 0, col = 0;
  unsigned int nelems;

  subvec->bytes = mat->bytes;
  subvec->nbytes = mat->nbytes;

  if (diag > 0)
    col += (unsigned int)diag;
  if (diag < 0)
    row += (unsigned int)(-diag);
  nelems = MIN (mat->nrows - row, mat->ncols - col);

  subvec->elems = intmat_get_elem (mat, row, col);
  subvec->nlimbs = mat->nlimbs;

  subvec->nelems = nelems;
  subvec->stride_elems = mat->stride_row * (mat->cpr + 1);
}

static inline void
intmat_set_diag (intmat_t mat, const intvec_t vec, int diag)
{
  intvec_t tmp;

  intmat_get_diag (tmp, mat, diag);
  intvec_set (tmp, vec);
}

static inline void
intmat_get_antidiag (intvec_t subvec, const intmat_t mat, int antidiag)
{
  unsigned int row = 0, col = mat->ncols - 1, nelems;

  subvec->bytes = mat->bytes;
  subvec->nbytes = mat->nbytes;

  if (antidiag > 0)
    col -= (unsigned int)antidiag;
  if (antidiag < 0)
    row += (unsigned int)(-antidiag);
  nelems = MIN (mat->nrows - row, col + 1);

  subvec->elems = intmat_get_elem (mat, row, col);
  subvec->nlimbs = mat->nlimbs;

  subvec->nelems = nelems;
  subvec->stride_elems = mat->stride_row * (mat->cpr - 1);
}

static inline void
intmat_set_antidiag (intmat_t mat, const intvec_t vec, int antidiag)
{
  intvec_t tmp;

  intmat_get_antidiag (tmp, mat, antidiag);
  intvec_set (tmp, vec);
}

static inline void
intmat_get_submat (intmat_t submat, const intmat_t mat, unsigned int row,
                   unsigned int col, unsigned int nrows, unsigned int ncols,
                   unsigned int stride_row, unsigned int stride_col)
{
  ASSERT_ERR (row + stride_row * (nrows - 1) < mat->nrows);
  ASSERT_ERR (col + stride_col * (ncols - 1) < mat->ncols);

  submat->bytes = mat->bytes;
  submat->nbytes = mat->nbytes;

  submat->cpr = mat->cpr;

  submat->elems = intmat_get_elem (mat, row, col);
  submat->nlimbs = mat->nlimbs;

  submat->nrows = nrows;
  submat->stride_row = stride_row * mat->stride_row;

  submat->ncols = ncols;
  submat->stride_col = stride_col * mat->stride_col;
}

static inline void
intmat_set_submat (intmat_t mat, const intmat_t submat, unsigned int row,
                   unsigned int col, unsigned int nrows, unsigned int ncols,
                   unsigned int stride_row, unsigned int stride_col)
{
  intmat_t tmp;

  intmat_get_submat (tmp, mat, row, col, nrows, ncols, stride_row, stride_col);
  intmat_set (tmp, submat);
}

static inline void
intmat_set (intmat_t r, const intmat_t a)
{
  unsigned int i, j;

  ASSERT_ERR (r->nrows == a->nrows);
  ASSERT_ERR (r->ncols == a->ncols);

  _MAT_FOREACH_ELEM (a, i, j)
  {
    intmat_set_elem (r, i, j, intmat_get_elem_src (a, i, j));
  }
}

static inline void
intmat_set_i64 (intmat_t r, const int64_t *a)
{
  unsigned int i, j;
  int_ptr rptr;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    rptr = intmat_get_elem (r, i, j);
    int_set_i64 (rptr, a[i * r->ncols + j]);
  }
}

static inline void
intmat_set_i32 (intmat_t r, const int32_t *a)
{
  unsigned int i, j;
  int_ptr rptr;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    rptr = intmat_get_elem (r, i, j);
    int_set_i64 (rptr, (int64_t)(a[i * r->ncols + j]));
  }
}

static inline void
intmat_set_i8 (intmat_t r, const int8_t *a)
{
  unsigned int i, j;
  int_ptr rptr;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    rptr = intmat_get_elem (r, i, j);
    int_set_i64 (rptr, (int64_t)(a[i * r->ncols + j]));
  }
}

static inline void
intmat_get_i64 (int64_t *r, const intmat_t a)
{
  unsigned int i, j;
  int_srcptr rptr;

  _MAT_FOREACH_ELEM (a, i, j)
  {
    rptr = intmat_get_elem_src (a, i, j);
    r[i * a->ncols + j] = int_get_i64 (rptr);
  }
}

static inline void
intmat_get_i32 (int32_t *r, const intmat_t a)
{
  unsigned int i, j;
  int_srcptr rptr;
  int64_t tmp;

  _MAT_FOREACH_ELEM (a, i, j)
  {
    rptr = intmat_get_elem_src (a, i, j);

    tmp = int_get_i64 (rptr);
    ASSERT_ERR (tmp >= INT32_MIN);
    ASSERT_ERR (tmp <= INT32_MAX);
    r[i * a->ncols + j] = (int32_t)tmp;
  }
}

static inline void
intmat_get_i8 (int8_t *r, const intmat_t a)
{
  unsigned int i, j;
  int_srcptr rptr;
  int64_t tmp;

  _MAT_FOREACH_ELEM (a, i, j)
  {
    rptr = intmat_get_elem_src (a, i, j);

    tmp = int_get_i64 (rptr);
    ASSERT_ERR (tmp >= INT8_MIN);
    ASSERT_ERR (tmp <= INT8_MAX);
    r[i * a->ncols + j] = (int8_t)tmp;
  }
}

static inline unsigned int
polyring_get_deg (const polyring_t ring)
{
  return ring->d;
}

static inline int_srcptr
polyring_get_mod (const polyring_t ring)
{
  return ring->q;
}

static inline unsigned int
polyring_get_log2q (const polyring_t ring)
{
  return ring->log2q;
}

static inline unsigned int
polyring_get_log2deg (const polyring_t ring)
{
  return ring->log2d;
}

static inline unsigned int
poly_get_nlimbs (const poly_t a)
{
  return a->ring->q->nlimbs;
}

static inline polyring_srcptr
poly_get_ring (const poly_t poly)
{
  return poly->ring;
}

static inline intvec_ptr
poly_get_coeffvec (poly_t poly)
{
  _fromcrt (poly);

  poly->crt = 0;
  return poly->coeffs;
}

static inline int_ptr
poly_get_coeff (poly_t poly, unsigned int idx)
{
  _fromcrt (poly);

  poly->crt = 0;
  return intvec_get_elem (poly->coeffs, idx);
}

static inline void
poly_set_coeff (poly_t poly, unsigned int idx, const int_t val)
{
  int_ptr coeff;

  coeff = poly_get_coeff (poly, idx);
  int_set (coeff, val);
}

static inline void
poly_set_zero (poly_t r)
{
  intvec_set_zero (r->coeffs);
  r->crt = 0;
}

static inline void
poly_set_one (poly_t r)
{
  intvec_ptr rcoeffs = r->coeffs;
  const unsigned int nelems = intvec_get_nelems (rcoeffs);
  int_ptr rcoeff;
  unsigned int i;

  rcoeff = intvec_get_elem (rcoeffs, 0);
  int_set_one (rcoeff);

  for (i = 1; i < nelems; i++)
    {
      rcoeff = intvec_get_elem (rcoeffs, i);
      int_set_zero (rcoeff);
    }
  r->crt = 0;
}

static inline void
poly_set_coeffvec_i64 (poly_t r, const int64_t *a)
{
  intvec_set_i64 (r->coeffs, a);
  r->crt = 0;
}

static inline void
poly_set_coeffvec_i32 (poly_t r, const int32_t *a)
{
  intvec_set_i32 (r->coeffs, a);
  r->crt = 0;
}

static inline void
poly_set_coeffvec_i16 (poly_t r, const int16_t *a)
{
  intvec_set_i16 (r->coeffs, a);
  r->crt = 0;
}

static inline void
poly_get_coeffvec_i64 (int64_t *r, poly_t a)
{
  _fromcrt (a);
  intvec_get_i64 (r, a->coeffs);
  a->crt = 0;
}

static inline void
poly_get_coeffvec_i32 (int32_t *r, poly_t a)
{
  _fromcrt (a);
  intvec_get_i32 (r, a->coeffs);
  a->crt = 0;
}

static inline void
poly_neg_self (poly_t a)
{
#ifdef XXX

#if DEBUGINFO == DEBUGINFO_ENABLED
  if (a->crt == 1)
    DEBUG_PRINTF (DEBUG_LEVEL >= 2, "%s", "implicit icrt neg self");
#endif

  _fromcrt (a);
  intvec_neg_self (a->coeffs);
  a->crt = 0;
#endif

  if (a->crt == 1)
    {
      polyring_srcptr ring = poly_get_ring (a);
      const unsigned int deg = polyring_get_deg (ring);
      unsigned int i;
      crtcoeff_t *c;

      _POLYRING_FOREACH_P (ring, i)
      {
        c = _get_crtcoeff (a->crtrep, i, 0, deg);
        hexl_ntt_scale (c, ring->moduli[i]->p - 1, c, deg, ring->moduli[i]->p,
                        1);
      }
    }
  else
    {
      intvec_neg_self (a->coeffs);
    }
}

static inline void
poly_set_coeffvec (poly_t r, const intvec_t v)
{
  ASSERT_ERR (polyring_get_deg (poly_get_ring (r)) == v->nelems);
  ASSERT_ERR (poly_get_nlimbs (r) == intvec_get_nlimbs (v));

  intvec_set (r->coeffs, v);
  r->crt = 0;
}

static inline void
poly_set_coeffvec2 (poly_t r, intvec_ptr v)
{
  ASSERT_ERR (polyring_get_deg (poly_get_ring (r)) == v->nelems);
  ASSERT_ERR (poly_get_nlimbs (r) == intvec_get_nlimbs (v));

  r->crt = 0;
  r->coeffs = v;
}

static inline unsigned int
polyvec_get_nelems (const polyvec_t a)
{
  return a->nelems;
}

static inline poly_ptr
polyvec_get_elem (const polyvec_t a, unsigned int elem)
{
  ASSERT_ERR (elem < a->nelems);

  return &(a->elems[elem * a->stride_elems]);
}

static inline polyring_srcptr
polyvec_get_ring (const polyvec_t a)
{
  return a->ring;
}

static inline unsigned int
polyvec_get_nlimbs (const polyvec_t a)
{
  return a->ring->q->nlimbs;
}

static inline poly_srcptr
polyvec_get_elem_src (const polyvec_t a, unsigned int elem)
{
  return polyvec_get_elem (a, elem);
}

static inline void
polyvec_set_zero (polyvec_t r)
{
  unsigned int i;
  poly_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = polyvec_get_elem (r, i);
    poly_set_zero (ri);
  }
}

static inline void
polyvec_set_one (polyvec_t r, unsigned int idx)
{
  unsigned int i;
  poly_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = polyvec_get_elem (r, i);

    if (i == idx)
      poly_set_one (ri);
    else
      poly_set_zero (ri);
  }
}

static inline void
polyvec_set_ones (polyvec_t r)
{
  unsigned int i;
  poly_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = polyvec_get_elem (r, i);
    poly_set_one (ri);
  }
}

static inline void
polyvec_set_elem (polyvec_t a, unsigned int idx, const poly_t elem)
{
  poly_ptr ptr;

  ASSERT_ERR (idx < a->nelems);

  ptr = polyvec_get_elem (a, idx);
  poly_set (ptr, elem);
}

static inline void
polyvec_neg_self (polyvec_t r)
{
  unsigned int i;
  poly_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = polyvec_get_elem (r, i);
    poly_neg_self (ri);
  }
}

static inline void
polyvec_set (polyvec_t r, const polyvec_t a)
{
  unsigned int i;
  poly_srcptr ai;

  ASSERT_ERR (r->nelems == a->nelems);

  _VEC_FOREACH_ELEM (r, i)
  {
    ai = polyvec_get_elem_src (a, i);
    polyvec_set_elem (r, i, ai);
  }
}

static inline void
polyvec_fill (polyvec_t r, poly_t a)
{
  unsigned int i;
  poly_ptr ri;

  _VEC_FOREACH_ELEM (r, i)
  {
    ri = polyvec_get_elem (r, i);
    poly_set (ri, a);
  }
}

static inline void
polyvec_set_coeffvec (polyvec_t r, const intvec_t v)
{
  const unsigned int d = polyring_get_deg (polyvec_get_ring (r));
  unsigned int i;
  intvec_t subv;
  poly_ptr poly;

  ASSERT_ERR (d * polyvec_get_nelems (r) == intvec_get_nelems (v));
  ASSERT_ERR (polyvec_get_nlimbs (r) == intvec_get_nlimbs (v));

  _VEC_FOREACH_ELEM (r, i)
  {
    poly = polyvec_get_elem (r, i);

    intvec_get_subvec (subv, v, i * d, d, 1);

    poly_set_coeffvec (poly, subv);
    poly->crt = 0;
  }
}

static inline void
polyvec_set_coeffvec2 (polyvec_t r, intvec_ptr v)
{
  const unsigned int d = polyring_get_deg (polyvec_get_ring (r));
  unsigned int i;
  intvec_ptr coeffvec;
  intvec_t subv;
  poly_ptr poly;

  ASSERT_ERR (d * polyvec_get_nelems (r) == intvec_get_nelems (v));
  ASSERT_ERR (polyvec_get_nlimbs (r) == intvec_get_nlimbs (v));

  _VEC_FOREACH_ELEM (r, i)
  {
    poly = polyvec_get_elem (r, i);
    coeffvec = poly->coeffs;

    intvec_get_subvec (subv, v, i * d, d, 1);

    memcpy (coeffvec, subv, sizeof (intvec_t));
    poly->crt = 0;
  }
}

static inline void
polyvec_set_coeffvec_i64 (polyvec_t r, const int64_t *a)
{
  unsigned int i;
  poly_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = polyvec_get_elem (r, i);
    poly_set_coeffvec_i64 (rptr, a + i * r->ring->d);
  }
}

static inline void
polyvec_set_coeffvec_i32 (polyvec_t r, const int32_t *a)
{
  unsigned int i;
  poly_ptr rptr;

  _VEC_FOREACH_ELEM (r, i)
  {
    rptr = polyvec_get_elem (r, i);
    poly_set_coeffvec_i32 (rptr, a + i * r->ring->d);
  }
}

static inline void
polyvec_get_coeffvec_i32 (int32_t *r, const polyvec_t a)
{
  unsigned int i;
  poly_ptr ptr;

  _VEC_FOREACH_ELEM (a, i)
  {
    ptr = polyvec_get_elem (a, i);
    poly_get_coeffvec_i32 (r + i * a->ring->d, ptr);
  }
}

static inline void
polyvec_get_coeffvec_i64 (int64_t *r, const polyvec_t a)
{
  unsigned int i;
  poly_ptr ptr;

  _VEC_FOREACH_ELEM (a, i)
  {
    ptr = polyvec_get_elem (a, i);
    poly_get_coeffvec_i64 (r + i * a->ring->d, ptr);
  }
}

static inline unsigned int
polymat_get_nlimbs (const polymat_t a)
{
  return a->ring->q->nlimbs;
}

static inline unsigned int
polymat_get_nrows (const polymat_t mat)
{
  return mat->nrows;
}

static inline unsigned int
polymat_get_ncols (const polymat_t mat)
{
  return mat->ncols;
}

static inline polyring_srcptr
polymat_get_ring (const polymat_t a)
{
  return a->ring;
}

static inline void
polymat_fill (polymat_t r, poly_t a)
{
  unsigned int i, j;
  poly_ptr ri;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    ri = polymat_get_elem (r, i, j);
    poly_set (ri, a);
  }
}

static inline void
polymat_set_zero (polymat_t r)
{
  unsigned int i, j;
  poly_ptr ri;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    ri = polymat_get_elem (r, i, j);
    poly_set_zero (ri);
  }
}

static inline void
polymat_set_one (polymat_t r)
{
  polyvec_t diag;
  unsigned int i, j;
  poly_ptr ri;

  polymat_get_diag (diag, r, 0);
  polyvec_set_ones (diag);

  _MAT_FOREACH_ELEM (r, i, j)
  {
    if (i != j)
      {
        ri = polymat_get_elem (r, i, j);
        poly_set_zero (ri);
      }
  }
}

static inline poly_ptr
polymat_get_elem (const polymat_t a, unsigned int row, unsigned int col)
{
  ASSERT_ERR (row < a->nrows);
  ASSERT_ERR (col < a->ncols);

  return &(a->elems[row * a->stride_row * a->cpr + col * a->stride_col]);
}

static inline poly_srcptr
polymat_get_elem_src (const polymat_t a, unsigned int row, unsigned int col)
{
  return polymat_get_elem (a, row, col);
}

static inline void
polymat_set_elem (polymat_t a, unsigned int row, unsigned int col,
                  const poly_t elem)
{
  poly_ptr ptr;

  ASSERT_ERR (row < a->nrows);
  ASSERT_ERR (col < a->ncols);

  ptr = polymat_get_elem (a, row, col);
  poly_set (ptr, elem);
}

static inline void
polymat_get_row (polyvec_t subvec, const polymat_t mat, unsigned int row)
{
  ASSERT_ERR (row < mat->nrows);

  subvec->elems = polymat_get_elem (mat, row, 0);
  subvec->ring = mat->ring;

  subvec->nelems = mat->ncols;
  subvec->stride_elems = mat->stride_col;
}

static inline void
polymat_set_row (polymat_t mat, const polyvec_t vec, unsigned int row)
{
  polyvec_t tmp;

  polymat_get_row (tmp, mat, row);
  polyvec_set (tmp, vec);
}

static inline void
polymat_get_col (polyvec_t subvec, const polymat_t mat, unsigned int col)
{
  ASSERT_ERR (col < mat->ncols);

  subvec->elems = polymat_get_elem (mat, 0, col);
  subvec->ring = mat->ring;

  subvec->nelems = mat->nrows;
  subvec->stride_elems = mat->stride_row * mat->cpr;
}

static inline void
polymat_set_col (polymat_t mat, const polyvec_t vec, unsigned int col)
{
  polyvec_t tmp;

  polymat_get_col (tmp, mat, col);
  polyvec_set (tmp, vec);
}

static inline void
polymat_get_diag (polyvec_t subvec, const polymat_t mat, int diag)
{
  unsigned int row = 0, col = 0;
  unsigned int nelems;

  if (diag > 0)
    col += (unsigned int)diag;
  if (diag < 0)
    row += (unsigned int)(-diag);
  nelems = MIN (mat->nrows - row, mat->ncols - col);

  subvec->elems = polymat_get_elem (mat, row, col);
  subvec->ring = mat->ring;

  subvec->nelems = nelems;
  subvec->stride_elems = mat->stride_row * (mat->cpr + 1);

  subvec->mem = NULL;
}

static inline void
polymat_set_diag (polymat_t mat, const polyvec_t vec, int diag)
{
  polyvec_t tmp;

  polymat_get_diag (tmp, mat, diag);
  polyvec_set (tmp, vec);
}

static inline void
polymat_get_antidiag (polyvec_t subvec, const polymat_t mat, int antidiag)
{
  unsigned int row = 0, col = mat->ncols - 1, nelems;

  if (antidiag > 0)
    col -= (unsigned int)antidiag;
  if (antidiag < 0)
    row += (unsigned int)(-antidiag);
  nelems = MIN (mat->nrows - row, col + 1);

  subvec->elems = polymat_get_elem (mat, row, col);
  subvec->ring = mat->ring;

  subvec->nelems = nelems;
  subvec->stride_elems = mat->stride_row * (mat->cpr - 1);

  subvec->mem = NULL;
}

static inline void
polymat_set_antidiag (polymat_t mat, const polyvec_t vec, int antidiag)
{
  polyvec_t tmp;

  polymat_get_antidiag (tmp, mat, antidiag);
  polyvec_set (tmp, vec);
}

static inline void
polymat_get_submat (polymat_t submat, const polymat_t mat, unsigned int row,
                    unsigned int col, unsigned int nrows, unsigned int ncols,
                    unsigned int stride_row, unsigned int stride_col)
{
  ASSERT_ERR (row + stride_row * (nrows - 1) < mat->nrows);
  ASSERT_ERR (col + stride_col * (ncols - 1) < mat->ncols);

  submat->cpr = mat->cpr;

  submat->elems = polymat_get_elem (mat, row, col);
  submat->ring = mat->ring;

  submat->nrows = nrows;
  submat->stride_row = stride_row * mat->stride_row;

  submat->ncols = ncols;
  submat->stride_col = stride_col * mat->stride_col;

  submat->mem = NULL;
}

static inline void
polymat_set_submat (polymat_t mat, const polymat_t submat, unsigned int row,
                    unsigned int col, unsigned int nrows, unsigned int ncols,
                    unsigned int stride_row, unsigned int stride_col)
{
  polymat_t tmp;

  polymat_get_submat (tmp, mat, row, col, nrows, ncols, stride_row,
                      stride_col);
  polymat_set (tmp, submat);
}

static inline void
polymat_set (polymat_t r, const polymat_t a)
{
  unsigned int i, j;

  ASSERT_ERR (r->nrows == a->nrows);
  ASSERT_ERR (r->ncols == a->ncols);

  _MAT_FOREACH_ELEM (a, i, j)
  {
    polymat_set_elem (r, i, j, polymat_get_elem_src (a, i, j));
  }
}

static inline void
polymat_set_i64 (polymat_t r, const int64_t *a)
{
  const unsigned int d = r->ring->d;
  unsigned int i, j;
  poly_ptr rptr;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    rptr = polymat_get_elem (r, i, j);
    poly_set_coeffvec_i64 (rptr, &a[d * (i * r->ncols + j)]);
  }
}

static inline void
polymat_set_i32 (polymat_t r, const int32_t *a)
{
  unsigned int i, j;
  poly_ptr rptr;

  _MAT_FOREACH_ELEM (r, i, j)
  {
    rptr = polymat_get_elem (r, i, j);
    poly_set_coeffvec_i32 (rptr, &a[i * r->ncols + j]);
  }
}

static inline void
polymat_get_i64 (int64_t *r, const polymat_t a)
{
  unsigned int i, j;
  poly_ptr rptr;

  _MAT_FOREACH_ELEM (a, i, j)
  {
    rptr = polymat_get_elem (a, i, j);
    poly_get_coeffvec_i64 (&r[i * a->ncols + j], rptr);
  }
}

static inline void
polymat_get_i32 (int32_t *r, const polymat_t a)
{
  unsigned int i, j;
  poly_ptr rptr;

  _MAT_FOREACH_ELEM (a, i, j)
  {
    rptr = polymat_get_elem (a, i, j);
    poly_get_coeffvec_i32 (&r[i * a->ncols + j], rptr);
  }
}

static inline unsigned int
dcompress_get_d (const dcompress_params_t params)
{
  return params->D;
}

static inline int_srcptr
dcompress_get_gamma (const dcompress_params_t params)
{
  return params->gamma;
}

static inline int_srcptr
dcompress_get_m (const dcompress_params_t params)
{
  return params->m;
}

static inline unsigned int
dcompress_get_log2m (const dcompress_params_t params)
{
  return params->log2m;
}

static inline polyring_srcptr
spolyvec_get_ring (spolyvec_ptr r)
{
  return r->ring;
}
static inline unsigned int
spolyvec_get_elem_ (spolyvec_ptr r, unsigned int i)
{
  ASSERT_ERR (i < r->nelems_max);
  return r->elems[i].elem;
}
static inline void
spolyvec_set_elem_ (spolyvec_ptr r, unsigned int i, unsigned int elem)
{
  ASSERT_ERR (i < r->nelems_max);
  r->elems[i].elem = elem;
}
static inline void
spolyvec_set_nelems (spolyvec_ptr r, unsigned int nelems)
{
  ASSERT_ERR (nelems < r->nelems_max);
  r->nelems = nelems;
}
static inline void
spolyvec_set_empty (spolyvec_ptr r)
{
  r->nelems = 0;
}
static inline poly_ptr
spolyvec_get_elem (spolyvec_ptr r, unsigned int i)
{
  ASSERT_ERR (i < r->nelems_max);
  return r->elems[i].poly;
}
static inline unsigned int
spolyvec_get_nelems (spolyvec_ptr r)
{
  return r->nelems;
}

static inline polyring_srcptr
spolymat_get_ring (spolymat_ptr r)
{
  return r->ring;
}
static inline unsigned int
spolymat_get_row (spolymat_ptr r, unsigned int i)
{
  ASSERT_ERR (i < r->nelems_max);
  return r->elems[i].row;
}
static inline unsigned int
spolymat_get_col (spolymat_ptr r, unsigned int i)
{
  ASSERT_ERR (i < r->nelems_max);
  return r->elems[i].col;
}
static inline void
spolymat_set_row (spolymat_ptr r, unsigned int i, unsigned int row)
{
  ASSERT_ERR (i < r->nelems_max);
  r->elems[i].row = row;
}
static inline void
spolymat_set_col (spolymat_ptr r, unsigned int i, unsigned int col)
{
  ASSERT_ERR (i < r->nelems_max);
  r->elems[i].col = col;
}
static inline void
spolymat_set_nelems (spolymat_ptr r, unsigned int nelems)
{
  ASSERT_ERR (nelems < r->nelems_max);
  r->nelems = nelems;
}
static inline void
spolymat_set_empty (spolymat_ptr r)
{
  r->nelems = 0;
}
static inline poly_ptr
spolymat_get_elem (spolymat_ptr r, unsigned int i)
{
  ASSERT_ERR (i < r->nelems_max);
  return r->elems[i].poly;
}
static inline unsigned int
spolymat_get_nrows (spolymat_ptr r)
{
  return r->nrows;
}
static inline unsigned int
spolymat_get_ncols (spolymat_ptr r)
{
  return r->ncols;
}

__END_DECLS
#endif

/* auto-generated by moduli.sage */
#ifndef MODULI_H
#define MODULI_H
#include <stdint.h>

/***********************************************************
 * degree 64 params
 */

#define NMODULI_D64 11
extern void *hexl_ntt_d64[];

static const crtcoeff_t roots_d64_p0[] = {29343744, -69174830805767, 48959125218339, 262485241596814, 412694376899749, 373927219197358, -70753781555832, 326412194788496, -396806682632790, 479719127649610, -509814162812394, 298275591901000, 554416974063345, 307703906411447, 59590449692171, 275285106938447, 548594139073435, -530395348501616, -461186107910784, 45147654470009, 73666197397104, 512321385516482, 298405660349717, 188894348288714, 170994764334521, -388147811785993, 493226774471532, -539613053681350, -312317357853293, 469164353125933, 65052930403110, -47514311282824, 338631562875440, 348786040326901, -215554776167931, -290740504661501, -471244635595924, 353610093688397, -357215168468612, -395700715951085, 468332895728365, 286731904201405, -110930914875246, 349703594188995, -431490514214663, 345395901411206, -411067679299929, 18034288803017, -173493646004075, 478567688637399, -239738563260274, -46195127494350, -177091583517774, 237852141494477, -33599907647133, -181765140212182, -519257143437216, -228244061030462, -339154796896709, -300990119183097, -248159931617846, 186735649070088, -235893542728171, 92385006320962};
static const crtcoeff_t k_d64_p0[] = {1};
static const limb_t P_d64_p0_limbs[] = {1125899906840833UL};
static const int_t P_d64_p0 = {{(limb_t *)P_d64_p0_limbs, 1, 0}};
static const limb_t Pp_d64_p0_0_limbs[] = {1UL};
static const int_t Pp_d64_p0_0 = {{(limb_t *)Pp_d64_p0_0_limbs, 1, 0}};
static const int_srcptr Pp_d64_p0[] = {Pp_d64_p0_0};
static const modulus_t d64_p0 = {{roots_d64_p0, 1125899906840833, -8444618314856986879, -264844594903297, -17592186044388, 1, P_d64_p0, Pp_d64_p0, k_d64_p0, 49}};

static const crtcoeff_t roots_d64_p1[] = {44023808, -57217240691719, -137835388992229, 214457320102392, 465549155769974, -191963792941052, -373069780643777, 187454533017737, 120263086181065, 440045783574, 460710204799341, -57382437301011, 235009568482602, 532395527144879, -112563847798382, 109271544012532, 491276276655063, 455295307156115, 14126360168935, -307397729338908, -200643242617219, -255682557266576, 328391055248971, -363851818557977, -453115252531572, -118947761796094, -313972252448513, -463824742517306, -197124575203904, 168073619657697, 362324873192210, -40975322727615, -391181295142760, -497494374589794, 220958898455263, 326131234254842, 283683663278317, -388085803588667, 127493564929429, -42186664498533, 469074939072918, 165874199031418, 189070389511811, -9522612050994, -64236777604642, -254519201139179, 343273575607286, -98663894858336, 359342729913756, -384465008611884, 73954271762143, 374112818864107, 68187207858536, -361167564619504, -53369401560165, -69523774956010, 69066204954751, -412227542642899, 378745524564280, 559538984957336, -426773890159564, 139404327688807, -119440196881499, -425191703663093};
static const crtcoeff_t k_d64_p1[] = {162099428551861, -162099428551732};
static const limb_t P_d64_p1_limbs[] = {13404964290873093761UL, 68719476735UL};
static const int_t P_d64_p1 = {{(limb_t *)P_d64_p1_limbs, 2, 0}};
static const limb_t Pp_d64_p1_0_limbs[] = {1125899906839937UL, 0UL};
static const int_t Pp_d64_p1_0 = {{(limb_t *)Pp_d64_p1_0_limbs, 2, 0}};
static const limb_t Pp_d64_p1_1_limbs[] = {1125899906840833UL, 0UL};
static const int_t Pp_d64_p1_1 = {{(limb_t *)Pp_d64_p1_1_limbs, 2, 0}};
static const int_srcptr Pp_d64_p1[] = {Pp_d64_p1_0, Pp_d64_p1_1};
static const modulus_t d64_p1 = {{roots_d64_p1, 1125899906839937, -2456608423348909439, -313704142859010, -17592186044374, -162099428551732, P_d64_p1, Pp_d64_p1, k_d64_p1, 99}};

static const crtcoeff_t roots_d64_p2[] = {81772544, -496652155992295, 423366446392861, 211027161252405, -30386852052015, 146331601556733, 209296190874385, -302039359940702, -492370199071994, -204105826168690, 249311850239195, -67018163184742, -90827354186324, 385260915959546, 222369263492538, -482842481712089, 363917195244277, 138109115642951, 134046358022459, 338863204250781, -529141023610761, -482685176875195, -22032450902115, -56023767616443, -364892273387359, 177152381602511, 523838004416886, -303601904259571, 470621782102806, -245317814050648, 484781183150266, 154873671982442, 11936851897956, -240587523356600, -340220723755047, -246423418972850, 430983207901093, -223096372096058, -125989410648068, -113588119817063, 552539253202630, 352556118966807, 457600481446338, 124317940306561, -158655807615250, 333206020849880, -410386145168258, 74129700678628, -346841344931952, -372720064339470, 396534084974229, 242501176163977, 273691176368006, 81609168167665, 252186048091332, 430031074847390, -57269269759328, 182694269053852, 509033155786985, 164682713997932, -202147012654616, -121972033533490, 155423528942295, -168186396749893};
static const crtcoeff_t k_d64_p2[] = {-521834894147971, 224859399555088, 296975494591860};
static const limb_t P_d64_p2_limbs[] = {15567817987894188801UL, 18446093368984340089UL, 4194303UL};
static const int_t P_d64_p2 = {{(limb_t *)P_d64_p2_limbs, 3, 0}};
static const limb_t Pp_d64_p2_0_limbs[] = {9802084588985295361UL, 68719476735UL, 0UL};
static const int_t Pp_d64_p2_0 = {{(limb_t *)Pp_d64_p2_0_limbs, 3, 0}};
static const limb_t Pp_d64_p2_1_limbs[] = {10810890905511814529UL, 68719476735UL, 0UL};
static const int_t Pp_d64_p2_1 = {{(limb_t *)Pp_d64_p2_1_limbs, 3, 0}};
static const limb_t Pp_d64_p2_2_limbs[] = {13404964290873093761UL, 68719476735UL, 0UL};
static const int_t Pp_d64_p2_2 = {{(limb_t *)Pp_d64_p2_2_limbs, 3, 0}};
static const int_srcptr Pp_d64_p2[] = {Pp_d64_p2_0, Pp_d64_p2_1, Pp_d64_p2_2};
static const modulus_t d64_p2 = {{roots_d64_p2, 1125899906837633, -5276763958930549887, -68650488793862, -17592186044338, 296975494591860, P_d64_p2, Pp_d64_p2, k_d64_p2, 149}};

static const crtcoeff_t roots_d64_p3[] = {268419072, 336238421527800, 316070935027490, 351238124101666, 23436250045608, -85310602592841, 129052447448090, -366640851656903, 345585095177476, 102474663296033, -114651964721787, 427277184855048, -10189598936231, 260196883219839, -303292867306671, -541245131056016, 531492805401932, 135501529061437, -1965358964196, -159364272337749, 479685885065800, -313492556453604, -493800737215921, 116043516212397, 323642159343622, -501574242758521, 28992337726558, 434642355916687, 450305034070214, -130050566527584, 350201713474494, -527195248390931, 44918735197600, 376279581489624, -394346427065004, 482992094701910, -460206249962657, -403802949706959, -339171894238510, 65869417934980, -305522679345582, -359909779473474, -80094410492908, -268175139850141, -138582209724904, -295462926422117, -501415728210637, 349021912768824, -450586655481540, -241637576748769, -495556239835834, -520426635250560, 273599095618747, 463519892364654, 282313902052128, -218861333051777, 362098807037778, -493563858157295, 313389532628126, -154705375835640, -301172880624024, 536358837549500, -375463138020318, 297047858853401};
static const crtcoeff_t k_d64_p3[] = {128196380219077, 169657750315280, -330126638371865, 32272507837893};
static const limb_t P_d64_p3_limbs[] = {4904813493768575745UL, 12527061842982023665UL, 18446743965278404608UL, 255UL};
static const int_t P_d64_p3 = {{(limb_t *)P_d64_p3_limbs, 4, 0}};
static const limb_t Pp_d64_p3_0_limbs[] = {1156298984617959937UL, 18445090614379815216UL, 4194303UL, 0UL};
static const int_t Pp_d64_p3_0 = {{(limb_t *)Pp_d64_p3_0_limbs, 4, 0}};
static const limb_t Pp_d64_p3_1_limbs[] = {3173911690943669633UL, 18445152187030969503UL, 4194303UL, 0UL};
static const int_t Pp_d64_p3_1 = {{(limb_t *)Pp_d64_p3_1_limbs, 4, 0}};
static const limb_t Pp_d64_p3_2_limbs[] = {8362058529278340737UL, 18445310516705366691UL, 4194303UL, 0UL};
static const int_t Pp_d64_p3_2 = {{(limb_t *)Pp_d64_p3_2_limbs, 4, 0}};
static const limb_t Pp_d64_p3_3_limbs[] = {15567817987894188801UL, 18446093368984340089UL, 4194303UL, 0UL};
static const int_t Pp_d64_p3_3 = {{(limb_t *)Pp_d64_p3_3_limbs, 4, 0}};
static const int_srcptr Pp_d64_p3[] = {Pp_d64_p3_0, Pp_d64_p3_1, Pp_d64_p3_2, Pp_d64_p3_3};
static const modulus_t d64_p3 = {{roots_d64_p3, 1125899906826241, 70936092446048257, -8795823538240, -17592186044160, 32272507837893, P_d64_p3, Pp_d64_p3, k_d64_p3, 199}};

static const crtcoeff_t roots_d64_p4[] = {289390592, -30545265818544, -232960902161961, 357304586224328, 271858260766994, -439558361774467, -60267869704971, -531796335327750, 308867119327935, -558012713630270, -243309196536556, 307658119318813, -378288500067609, 189880241623103, 238684687898840, -356307556618608, -513547847663673, -389113137100374, -209653088787894, 538519640568766, 317200610181647, 453693669978612, 231512652308618, 197892276336395, 395513436031733, 236432148937727, 26474192830112, 502943058890287, -323415996906497, -156212339503167, -217649173378908, -140922551083065, -183006659178044, -520732739459749, -502504696149440, 532245520071994, 420128980377385, 527715521224583, 426554980048413, 279323213763523, 158968236198982, -459465270246211, -441332226082046, -335754408134486, 218845670829575, -105423245880765, -470485246104427, 127107196866838, 481876382162354, 540261031086080, -374999461221636, 506258429042222, 295677622571897, 120713895067542, 141336338705591, -490360329712776, -238710301949572, -162361270646285, 499533145260287, -423755362099709, -432817459770358, 512588883678982, -123820431388453, 91516020889338};
static const crtcoeff_t k_d64_p4[] = {395319555471506, 434229981581007, 31922995043646, 398437801003476, -134010426262513};
static const limb_t P_d64_p4_limbs[] = {18419519835413616129UL, 17596761229628551441UL, 2679810526530129UL, 288230376140571904UL};
static const int_t P_d64_p4 = {{(limb_t *)P_d64_p4_limbs, 4, 0}};
static const limb_t Pp_d64_p4_0_limbs[] = {6637682978512313601UL, 1877280177139060238UL, 18446743898706411522UL, 255UL};
static const int_t Pp_d64_p4_0 = {{(limb_t *)Pp_d64_p4_0_limbs, 4, 0}};
static const limb_t Pp_d64_p4_1_limbs[] = {9662807870886666369UL, 17920412667718193760UL, 18446743902464507905UL, 255UL};
static const int_t Pp_d64_p4_1 = {{(limb_t *)Pp_d64_p4_1_limbs, 4, 0}};
static const limb_t Pp_d64_p4_2_limbs[] = {17443833940008790401UL, 12246352126303835904UL, 18446743912128184321UL, 255UL};
static const int_t Pp_d64_p4_2 = {{(limb_t *)Pp_d64_p4_2_limbs, 4, 0}};
static const limb_t Pp_d64_p4_3_limbs[] = {581388595522655745UL, 13359963891252777145UL, 18446743959909695488UL, 255UL};
static const int_t Pp_d64_p4_3 = {{(limb_t *)Pp_d64_p4_3_limbs, 4, 0}};
static const limb_t Pp_d64_p4_4_limbs[] = {4904813493768575745UL, 12527061842982023665UL, 18446743965278404608UL, 255UL};
static const int_t Pp_d64_p4_4 = {{(limb_t *)Pp_d64_p4_4_limbs, 4, 0}};
static const int_srcptr Pp_d64_p4[] = {Pp_d64_p4_0, Pp_d64_p4_1, Pp_d64_p4_2, Pp_d64_p4_3, Pp_d64_p4_4};
static const modulus_t d64_p4 = {{roots_d64_p4, 1125899906824961, 8941995416230642945, 430321633063350, -17592186044140, -134010426262513, P_d64_p4, Pp_d64_p4, k_d64_p4, 249}};

static const crtcoeff_t roots_d64_p5[] = {327139328, 360984481833569, -46694848214382, 226313967773885, 89006173110395, -554565270894748, -98142519694482, 69546835308817, -541053536052130, -557051614707854, -444136915744666, -142841865802716, 529589234250771, -521596007276002, -216279266392088, 553096926914183, -483695936082938, -416795642699652, -302222302417936, 545836590079215, 160394332096776, -423935788977371, 168196978411273, -43530363421598, -171792450769079, -190765478913316, -407365767065455, 457015279520404, 104168764093458, -409964567610915, -96769026476511, 512207928908281, -384621557500678, 124346218671498, -466922950863064, -25033420818682, 372572936706744, -139495371280150, 257466491732075, -256430137313246, -42304029894270, 400331460688529, -9371127006114, 15276343620370, -316485617413645, -402989257676073, 292791592351427, 385450373891699, -436376762311200, -426397293116960, -378600570501982, 3667315014973, -157029538710847, 554029034654044, 11155246813906, -281499849452476, 211907333747311, -18845719859225, 210234390824230, 148005714528216, -374590900391041, -209220648272097, -40086826354583, 372682027831351};
static const crtcoeff_t k_d64_p5[] = {246888298256607, 538882170109464, 485812852229550, -335619290817921, 507788200354773, -317852323291127};
static const limb_t P_d64_p5_limbs[] = {14972982092611373057UL, 14746452920664392075UL, 4807031112944064362UL, 1729382642902109948UL, 17592186043424UL};
static const int_t P_d64_p5 = {{(limb_t *)P_d64_p5_limbs, 5, 0}};
static const limb_t Pp_d64_p5_0_limbs[] = {13599944456069172993UL, 4182053839030596997UL, 5860667600876824UL, 288230376135918848UL, 0UL};
static const int_t Pp_d64_p5_0 = {{(limb_t *)Pp_d64_p5_0_limbs, 5, 0}};
static const limb_t Pp_d64_p5_1_limbs[] = {6580122058970436225UL, 18358628421483347382UL, 5638924881839422UL, 288230376136148224UL, 0UL};
static const int_t Pp_d64_p5_1 = {{(limb_t *)Pp_d64_p5_1_limbs, 5, 0}};
static const limb_t Pp_d64_p5_2_limbs[] = {3905262064729004929UL, 13756898523744205248UL, 5099653083130107UL, 288230376136738048UL, 0UL};
static const int_t Pp_d64_p5_2 = {{(limb_t *)Pp_d64_p5_2_limbs, 5, 0}};
static const limb_t Pp_d64_p5_3_limbs[] = {758129737685207041UL, 4787046255961707169UL, 3087669210890286UL, 288230376139654400UL, 0UL};
static const int_t Pp_d64_p5_3 = {{(limb_t *)Pp_d64_p5_3_limbs, 5, 0}};
static const limb_t Pp_d64_p5_4_limbs[] = {7136603302860688641UL, 5954006280784754093UL, 2929635889234997UL, 288230376139982080UL, 0UL};
static const int_t Pp_d64_p5_4 = {{(limb_t *)Pp_d64_p5_4_limbs, 5, 0}};
static const limb_t Pp_d64_p5_5_limbs[] = {18419519835413616129UL, 17596761229628551441UL, 2679810526530129UL, 288230376140571904UL, 0UL};
static const int_t Pp_d64_p5_5 = {{(limb_t *)Pp_d64_p5_5_limbs, 5, 0}};
static const int_srcptr Pp_d64_p5[] = {Pp_d64_p5_0, Pp_d64_p5_1, Pp_d64_p5_2, Pp_d64_p5_3, Pp_d64_p5_4, Pp_d64_p5_5};
static const modulus_t d64_p5 = {{roots_d64_p5, 1125899906822657, 6717599665002663425, 59648776139169, -17592186044104, -317852323291127, P_d64_p5, Pp_d64_p5, k_d64_p5, 299}};

static const crtcoeff_t roots_d64_p6[] = {369082368, -300489023163428, 421347163950709, 119388681941738, 360144383997281, 511062208936740, 231338438161156, 120059243719409, 124113795002142, -475066130675007, 298848858017690, 305681270877881, -531119894792160, 172245187463572, 75805070946510, -508465332023459, -307465930108778, 479649956626004, 503844164910008, 336209203777636, -541321571801292, 326949571339385, 222379463637849, 548345646052417, 259314458597312, 165322140821889, 394266116964101, 289245256367522, 17128898609526, -298101406446035, -462871123139251, -371435563149069, -349551718119447, -406582504710993, -454654319837679, -366268854140503, 224298276320353, -429029981745351, 483344802919165, 532564250326929, -369755082248156, 477191977296355, -7118667122184, -318555014989876, 71799573419153, -432659129568632, -439575341305099, 8008265510960, 101106193389107, -203189416493259, -221996364267934, 322682890348346, -472763840709054, 135692932553300, -409622502713981, -306103769137724, -59259970337120, 194082559402853, -532101726835202, -265139805421473, -369806461529513, -150192653263894, -150742428584027, -57989963437028};
static const crtcoeff_t k_d64_p6[] = {-543903658136713, 299153499329135, 257691401299842, 117152613892055, 286231578236456, 4082402923709, -420407837543331};
static const limb_t P_d64_p6_limbs[] = {4654756431870980097UL, 14514723970059148201UL, 1147375477802919413UL, 6039932459285591342UL, 16933657744261279616UL, 1073741823UL};
static const int_t P_d64_p6 = {{(limb_t *)P_d64_p6_limbs, 6, 0}};
static const limb_t Pp_d64_p6_0_limbs[] = {1901395840155744001UL, 13821937290807193812UL, 12407436257129098509UL, 1729382970383601397UL, 17592186043100UL, 0UL};
static const int_t Pp_d64_p6_0 = {{(limb_t *)Pp_d64_p6_0_limbs, 6, 0}};
static const limb_t Pp_d64_p6_1_limbs[] = {12959141761653455489UL, 10520306086148984038UL, 3611225899507221833UL, 1729382951682346742UL, 17592186043114UL, 0UL};
static const int_t Pp_d64_p6_1 = {{(limb_t *)Pp_d64_p6_1_limbs, 6, 0}};
static const limb_t Pp_d64_p6_2_limbs[] = {6611416614636536705UL, 1846192442087641867UL, 7613235015722253013UL, 1729382905480842999UL, 17592186043150UL, 0UL};
static const int_t Pp_d64_p6_2 = {{(limb_t *)Pp_d64_p6_2_limbs, 6, 0}};
static const limb_t Pp_d64_p6_3_limbs[] = {5603380329506320385UL, 7244309784960821391UL, 4283135554943697200UL, 1729382716982431483UL, 17592186043328UL, 0UL};
static const int_t Pp_d64_p6_3 = {{(limb_t *)Pp_d64_p6_3_limbs, 6, 0}};
static const limb_t Pp_d64_p6_4_limbs[] = {860119625888412929UL, 15848098907616518962UL, 9004026221414589000UL, 1729382699955195643UL, 17592186043348UL, 0UL};
static const int_t Pp_d64_p6_4 = {{(limb_t *)Pp_d64_p6_4_limbs, 6, 0}};
static const limb_t Pp_d64_p6_5_limbs[] = {10880055835368013313UL, 13986733070297746831UL, 16393460238736483296UL, 1729382671420100347UL, 17592186043384UL, 0UL};
static const int_t Pp_d64_p6_5 = {{(limb_t *)Pp_d64_p6_5_limbs, 6, 0}};
static const limb_t Pp_d64_p6_6_limbs[] = {14972982092611373057UL, 14746452920664392075UL, 4807031112944064362UL, 1729382642902109948UL, 17592186043424UL, 0UL};
static const int_t Pp_d64_p6_6 = {{(limb_t *)Pp_d64_p6_6_limbs, 6, 0}};
static const int_srcptr Pp_d64_p6[] = {Pp_d64_p6_0, Pp_d64_p6_1, Pp_d64_p6_2, Pp_d64_p6_3, Pp_d64_p6_4, Pp_d64_p6_5, Pp_d64_p6_6};
static const modulus_t d64_p6 = {{roots_d64_p6, 1125899906820097, -3382455769235433471, -12094356744313, -17592186044064, -420407837543331, P_d64_p6, Pp_d64_p6, k_d64_p6, 349}};

static const crtcoeff_t roots_d64_p7[] = {383762432, 233099629676533, 285929256870978, 14454676388869, -506899410876541, 59687356782799, 59222944227176, 450836363001726, 358035575769168, -185616725293139, 134723342375347, -5964776491328, -83207970273242, 177248282079575, 499520186800662, 194284327212527, -441699010104146, 333537628769286, 184146721079740, -28487077287949, 541217206507674, -418702800625603, -205237980431831, 154436020575954, 42956689099880, 321445060966777, 462342248819996, -201600526752757, -379781109210201, 112112726766992, 326593895040231, 380751247120839, 384847864371, 309860272982617, 274140441491262, 341702940278074, -554914771950, 557549910333933, 472793081340016, -101227712157628, -529725355717079, -364640763218695, 559705936518140, 139390832823492, 172626071950698, -502511820225322, 297085563638354, -360080858240105, -344643780340375, 323245413494281, -105918962630958, 146905222178057, 451023849594409, -145624713345219, 385043330285816, 233597895159270, 27443839004454, 561885826785599, -194600289733619, 101339776262704, 100507632714269, 387148367328244, 559396023397619, -120662302427110};
static const crtcoeff_t k_d64_p7[] = {559175601093251, -417937439064734, -523748019348262, -170340987696568, -442590906359366, -230328505939393, 117331583897112, -17461233410712};
static const limb_t P_d64_p7_limbs[] = {5733755864672244865UL, 3086509115746710428UL, 12871554120270490971UL, 10070378794142386236UL, 70296512544542161UL, 18446626571994272371UL, 65535UL};
static const int_t P_d64_p7 = {{(limb_t *)P_d64_p7_limbs, 7, 0}};
static const limb_t Pp_d64_p7_0_limbs[] = {9899226555116854145UL, 3195195913255196915UL, 3612533735119969317UL, 6024498604190834136UL, 16553103575776938388UL, 1073741823UL, 0UL};
static const int_t Pp_d64_p7_0 = {{(limb_t *)Pp_d64_p7_0_limbs, 7, 0}};
static const limb_t Pp_d64_p7_1_limbs[] = {16058852586565902081UL, 16643137273883532481UL, 12548062556830539459UL, 6025525665511886674UL, 16568866174471265768UL, 1073741823UL, 0UL};
static const int_t Pp_d64_p7_1 = {{(limb_t *)Pp_d64_p7_1_limbs, 7, 0}};
static const limb_t Pp_d64_p7_2_limbs[] = {2215066376524408833UL, 1291703331057428955UL, 16828478467504076481UL, 6027978006492618614UL, 16609398571113937088UL, 1073741823UL, 0UL};
static const int_t Pp_d64_p7_2 = {{(limb_t *)Pp_d64_p7_2_limbs, 7, 0}};
static const limb_t Pp_d64_p7_3_limbs[] = {14442810372106376321UL, 1374457579077220046UL, 8299629189291520809UL, 6036693551272015947UL, 16809808754516249836UL, 1073741823UL, 0UL};
static const int_t Pp_d64_p7_3 = {{(limb_t *)Pp_d64_p7_3_limbs, 7, 0}};
static const limb_t Pp_d64_p7_4_limbs[] = {12539867142481893761UL, 3954692813771322780UL, 10200675401029418657UL, 6037380520516557490UL, 16832326752651594596UL, 1073741823UL, 0UL};
static const int_t Pp_d64_p7_4 = {{(limb_t *)Pp_d64_p7_4_limbs, 7, 0}};
static const limb_t Pp_d64_p7_5_limbs[] = {16092955693792715393UL, 6834706140071332146UL, 13746584840259210169UL, 6038499913313512622UL, 16872859149295344188UL, 1073741823UL, 0UL};
static const int_t Pp_d64_p7_5 = {{(limb_t *)Pp_d64_p7_5_limbs, 7, 0}};
static const limb_t Pp_d64_p7_6_limbs[] = {18092487112634297473UL, 9561663830802805329UL, 10585611527956328489UL, 6039586610597413444UL, 16917895145566371628UL, 1073741823UL, 0UL};
static const int_t Pp_d64_p7_6 = {{(limb_t *)Pp_d64_p7_6_limbs, 7, 0}};
static const limb_t Pp_d64_p7_7_limbs[] = {4654756431870980097UL, 14514723970059148201UL, 1147375477802919413UL, 6039932459285591342UL, 16933657744261279616UL, 1073741823UL, 0UL};
static const int_t Pp_d64_p7_7 = {{(limb_t *)Pp_d64_p7_7_limbs, 7, 0}};
static const int_srcptr Pp_d64_p7[] = {Pp_d64_p7_0, Pp_d64_p7_1, Pp_d64_p7_2, Pp_d64_p7_3, Pp_d64_p7_4, Pp_d64_p7_5, Pp_d64_p7_6, Pp_d64_p7_7};
static const modulus_t d64_p7 = {{roots_d64_p7, 1125899906819201, 2277140613001681793, -219283578760707, -17592186044050, -17461233410712, P_d64_p7, Pp_d64_p7, k_d64_p7, 399}};

static const crtcoeff_t roots_d64_p8[] = {406831104, -31993252316301, -540205155977758, -243824982313753, 75177629376752, -378238621042086, -521085524439760, -88018990938654, -543086189747840, 475720685282593, 223858803733240, 15821159353624, -501585871538476, 308023817978837, -522834070298570, 369643368578243, -513390779336543, -343481816686194, 258143770158127, 245643917831978, 48694002827933, -561747339512589, -395387706048458, -50162635535330, 255864694258700, -554761412718974, 298261484969274, 292807999500173, 298168351307373, -161131935882137, 289737292000146, -483975133651927, 263638435171730, -20267549184063, 317208055430989, -154470338596066, -40405076055527, 548916002543152, 292278345509312, -2413585233620, 530409486814240, -361224042112583, -159067316435838, 299709136333259, -419964247081855, 300834936503622, -299000435390671, 295760299606679, -150261024173418, 94701187150906, 291218540337143, 34094829307178, 57673550149742, 265059273517200, -430198258961711, -160069765679810, 62199100895427, 87111564874557, -160191099274809, 416039373936446, -23946396708425, -19712332071189, -214141676050845, 371334838006055};
static const crtcoeff_t k_d64_p8[] = {269087309521327, 50558275146223, 346535714675904, 384915870253537, 471595160601966, -518690658446471, 11677198862754, 185529999726893, -75308963507827};
static const limb_t P_d64_p8_limbs[] = {2988733824824062849UL, 1542768612800615390UL, 7800472859045847674UL, 8861008478030225486UL, 10890906626526548428UL, 8235314642675272638UL, 18446744064910491648UL, 3UL};
static const int_t P_d64_p8 = {{(limb_t *)P_d64_p8_limbs, 8, 0}};
static const limb_t Pp_d64_p8_0_limbs[] = {3097653317248924289UL, 6728265890830275920UL, 11803557533674314692UL, 17371692901699798684UL, 2997634556863735916UL, 18446601832982649776UL, 65535UL, 0UL};
static const int_t Pp_d64_p8_0 = {{(limb_t *)Pp_d64_p8_0_limbs, 8, 0}};
static const limb_t Pp_d64_p8_1_limbs[] = {14834331922072616449UL, 4954564881935167950UL, 11880277951780682704UL, 6129926840110700645UL, 4837355103817010576UL, 18446602795055323969UL, 65535UL, 0UL};
static const int_t Pp_d64_p8_1 = {{(limb_t *)Pp_d64_p8_1_limbs, 8, 0}};
static const limb_t Pp_d64_p8_2_limbs[] = {17407973270262499073UL, 16666683392632987085UL, 3479748908567804525UL, 5228559839612192905UL, 2238778359462777982UL, 18446605268956486187UL, 65535UL, 0UL};
static const int_t Pp_d64_p8_2 = {{(limb_t *)Pp_d64_p8_2_limbs, 8, 0}};
static const limb_t Pp_d64_p8_3_limbs[] = {18083779898689024897UL, 13117647508409273285UL, 13678387155508388325UL, 17330621455061880419UL, 12288561849103816452UL, 18446617501023343968UL, 65535UL, 0UL};
static const int_t Pp_d64_p8_3 = {{(limb_t *)Pp_d64_p8_3_limbs, 8, 0}};
static const limb_t Pp_d64_p8_4_limbs[] = {10949949741102790785UL, 8494061294485852307UL, 17323787726060161882UL, 10188404654066385088UL, 6105119640091595943UL, 18446618875412878566UL, 65535UL, 0UL};
static const int_t Pp_d64_p8_4 = {{(limb_t *)Pp_d64_p8_4_limbs, 8, 0}};
static const limb_t Pp_d64_p8_5_limbs[] = {17579110080241631617UL, 108664633399160072UL, 483414222887283537UL, 6023365782823161876UL, 47778273785549721UL, 18446621349314040850UL, 65535UL, 0UL};
static const int_t Pp_d64_p8_5 = {{(limb_t *)Pp_d64_p8_5_limbs, 8, 0}};
static const limb_t Pp_d64_p8_6_limbs[] = {10285054938837519233UL, 16872211028997411272UL, 10218259152916887472UL, 3707859554703728402UL, 17656852949616426719UL, 18446624098093110065UL, 65535UL, 0UL};
static const int_t Pp_d64_p8_6 = {{(limb_t *)Pp_d64_p8_6_limbs, 8, 0}};
static const limb_t Pp_d64_p8_7_limbs[] = {430845957223091969UL, 5347592942649233593UL, 2233615786490946951UL, 9794494100133071589UL, 9120279899113081860UL, 18446625060165784294UL, 65535UL, 0UL};
static const int_t Pp_d64_p8_7 = {{(limb_t *)Pp_d64_p8_7_limbs, 8, 0}};
static const limb_t Pp_d64_p8_8_limbs[] = {5733755864672244865UL, 3086509115746710428UL, 12871554120270490971UL, 10070378794142386236UL, 70296512544542161UL, 18446626571994272371UL, 65535UL, 0UL};
static const int_t Pp_d64_p8_8 = {{(limb_t *)Pp_d64_p8_8_limbs, 8, 0}};
static const int_srcptr Pp_d64_p8[] = {Pp_d64_p8_0, Pp_d64_p8_1, Pp_d64_p8_2, Pp_d64_p8_3, Pp_d64_p8_4, Pp_d64_p8_5, Pp_d64_p8_6, Pp_d64_p8_7, Pp_d64_p8_8};
static const modulus_t d64_p8 = {{roots_d64_p8, 1125899906817793, -7715290210673532671, 4260879643245, -17592186044028, -75308963507827, P_d64_p8, Pp_d64_p8, k_d64_p8, 449}};

static const crtcoeff_t roots_d64_p9[] = {446676992, 467704323956308, 60307751780128, 461426351456276, -162105854571975, -82591332592537, -359012900519106, -505586890336879, -493633959529064, 158188946446404, 532827966396551, -10693653120888, -82591133175025, -13498042848739, -494013181619418, 364150094403581, 310672716863778, 469643463972923, 406124663969014, 103025553116846, -168914263532489, -428973693237701, -369639868334967, 552605919459645, 57213019760211, -75860350492670, -89620949694936, -162038387110217, 182128342580979, 3252816968915, -542168784174360, -67216547614139, -112193476171245, 524340846179270, -123106652672573, 470865018729825, 347973480641534, 340633297978898, -77611095066276, -424960153109679, -115474699269110, 258988150205590, 557562622696829, 225851284379481, 23429594513226, 40070901824242, -223140476570644, -513230950119509, -334219840977256, -204181852447978, -80267065367484, -503507697785953, 129478863663474, 541093493910477, -311277159818329, -74625208364368, -778723825330, -491150349876442, 538407818782126, 555441929279095, 471171331024671, 173642945174153, -334678846399920, 324136594910587};
static const crtcoeff_t k_d64_p9[] = {-303453672572701, -6644939972613, -145606064448952, 539837766364177, 493235772181790, -1009129480443, 38510157877110, 425975790262649, -468013773367303, 553067999971776};
static const limb_t P_d64_p9_limbs[] = {12263297668384033025UL, 3802306618637875953UL, 18158156371391781627UL, 10197921094918803016UL, 5135392244264989569UL, 17770881784860906014UL, 742532487879010UL, 4503599626724392UL};
static const int_t P_d64_p9 = {{(limb_t *)P_d64_p9_limbs, 8, 0}};
static const limb_t Pp_d64_p9_0_limbs[] = {14734584189686386689UL, 7853186219456441128UL, 11064632498883792943UL, 17596256525482294947UL, 6217195277279410712UL, 11858470438318936979UL, 18446744063241158656UL, 3UL};
static const int_t Pp_d64_p9_0 = {{(limb_t *)Pp_d64_p9_0_limbs, 8, 0}};
static const limb_t Pp_d64_p9_1_limbs[] = {15897289763780350849UL, 5113860730863273642UL, 13154728571770685617UL, 14337835903359206010UL, 17317430277734789605UL, 11707378848973918865UL, 18446744063299878912UL, 3UL};
static const int_t Pp_d64_p9_1 = {{(limb_t *)Pp_d64_p9_1_limbs, 8, 0}};
static const limb_t Pp_d64_p9_2_limbs[] = {6274999765800574081UL, 5001243148219406020UL, 1604634890729785567UL, 12671597963669192933UL, 10368515908453345059UL, 11326774102948504623UL, 18446744063450873856UL, 3UL};
static const int_t Pp_d64_p9_2 = {{(limb_t *)Pp_d64_p9_2_limbs, 8, 0}};
static const limb_t Pp_d64_p9_3_limbs[] = {4435726274310719745UL, 3996775410708116916UL, 15279407616443301825UL, 14317498863807877450UL, 13339034623833653214UL, 9612425468614475630UL, 18446744064197459968UL, 3UL};
static const int_t Pp_d64_p9_3 = {{(limb_t *)Pp_d64_p9_3_limbs, 8, 0}};
static const limb_t Pp_d64_p9_4_limbs[] = {11465695308767186433UL, 11609891418546156827UL, 15282871246809145909UL, 4813408248776039702UL, 7048283922450974358UL, 9437218290736549461UL, 18446744064281346048UL, 3UL};
static const int_t Pp_d64_p9_4 = {{(limb_t *)Pp_d64_p9_4_limbs, 8, 0}};
static const limb_t Pp_d64_p9_5_limbs[] = {6013132884392171265UL, 1935598502039442613UL, 4138420751949520335UL, 2528640576393127311UL, 12788758487637262334UL, 9130711832321821355UL, 18446744064432340992UL, 3UL};
static const int_t Pp_d64_p9_5 = {{(limb_t *)Pp_d64_p9_5_limbs, 8, 0}};
static const limb_t Pp_d64_p9_6_limbs[] = {10819642157258793217UL, 6046662590838429069UL, 18381574058530216334UL, 9738515572665649422UL, 7126223368527081620UL, 8803519162142453641UL, 18446744064600113152UL, 3UL};
static const int_t Pp_d64_p9_6 = {{(limb_t *)Pp_d64_p9_6_limbs, 8, 0}};
static const limb_t Pp_d64_p9_7_limbs[] = {8747224722010547329UL, 16458766952184118404UL, 8451847008751056160UL, 10914830260811068285UL, 936345933021171157UL, 8692326650741787220UL, 18446744064658833408UL, 3UL};
static const int_t Pp_d64_p9_7 = {{(limb_t *)Pp_d64_p9_7_limbs, 8, 0}};
static const limb_t Pp_d64_p9_8_limbs[] = {4232990666345572865UL, 2977437116588361450UL, 8305545446320898147UL, 14975911010031443885UL, 5950484781585976092UL, 8521078814234396469UL, 18446744064751108096UL, 3UL};
static const int_t Pp_d64_p9_8 = {{(limb_t *)Pp_d64_p9_8_limbs, 8, 0}};
static const limb_t Pp_d64_p9_9_limbs[] = {2988733824824062849UL, 1542768612800615390UL, 7800472859045847674UL, 8861008478030225486UL, 10890906626526548428UL, 8235314642675272638UL, 18446744064910491648UL, 3UL};
static const int_t Pp_d64_p9_9 = {{(limb_t *)Pp_d64_p9_9_limbs, 8, 0}};
static const int_srcptr Pp_d64_p9[] = {Pp_d64_p9_0, Pp_d64_p9_1, Pp_d64_p9_2, Pp_d64_p9_3, Pp_d64_p9_4, Pp_d64_p9_5, Pp_d64_p9_6, Pp_d64_p9_7, Pp_d64_p9_8, Pp_d64_p9_9};
static const modulus_t d64_p9 = {{roots_d64_p9, 1125899906815361, -4189193719969305983, 236051675849167, -17592186043990, 553067999971776, P_d64_p9, Pp_d64_p9, k_d64_p9, 499}};

static const crtcoeff_t roots_d64_p10[] = {465551360, -445728664760104, -354607522289887, -81978481825634, -357183757521746, 111981532800004, 351201501928606, 219232232835229, 185534010588194, -207785838302105, 137967918483773, 241068198288118, -308748781264927, 439728032982631, -28842499987492, 25714392066632, 183529216429884, -328966399879956, -118062025858268, 469462777080386, -381037213130125, -185783166671994, 67565752364918, 389940585649400, -227742775180933, 374379887621867, -272907757233251, -495262924298710, -361962063983329, 152099671452892, 159119695861151, -276264439351814, 519309149253831, 529828047088465, -285719337881248, 420696051656471, -154277594375932, -512677278208111, -228043157516132, -384756376648919, 70303744026815, 514440751400739, -53358894144314, -316657702679032, 43724543164066, 22486393413342, 548169506221673, 391623101695115, 451301116083191, 399604247791004, -222105094439148, 545165716044064, -146465470778702, -323641697851788, -410299517606348, 340853174114046, -47917716419036, 470556238969183, -320201174044276, -59929501491482, -134391376575862, -213078725074071, -484635225955876, -32953610891917};
static const crtcoeff_t k_d64_p10[] = {-109474587031939, 475908276268046, 15771891030874, -549426378884909, -452625802926866, -476988015789395, 120461690071125, 373635851323949, 400038670522438, 562469859657705, -359771454242051};
static const limb_t P_d64_p10_limbs[] = {18434248600113420801UL, 17026923308236275142UL, 17642015363333897013UL, 10092140130886581307UL, 6420614956302114696UL, 6788594110025664527UL, 4664865673837265108UL, 11578754705649176793UL, 274877906897UL};
static const int_t P_d64_p10 = {{(limb_t *)P_d64_p10_limbs, 9, 0}};
static const limb_t Pp_d64_p10_0_limbs[] = {7153302965349490945UL, 14416475308116830175UL, 9438619157118211764UL, 976682582070958055UL, 1162903353040818253UL, 13878753520458675985UL, 1021242982028935UL, 4503599626617896UL, 0UL};
static const int_t Pp_d64_p10_0 = {{(limb_t *)Pp_d64_p10_0_limbs, 9, 0}};
static const limb_t Pp_d64_p10_1_limbs[] = {8001857415695819905UL, 15018900738565269333UL, 15714982204335719070UL, 5897041439170224541UL, 6498818990398193380UL, 8765090913435109189UL, 1010352547191194UL, 4503599626621480UL, 0UL};
static const int_t Pp_d64_p10_1 = {{(limb_t *)Pp_d64_p10_1_limbs, 9, 0}};
static const limb_t Pp_d64_p10_2_limbs[] = {10325562873444035969UL, 9954414856633568721UL, 7208154063251295660UL, 17246110168138591443UL, 2851227093066887718UL, 487562409859945008UL, 982831755714868UL, 4503599626630696UL, 0UL};
static const int_t Pp_d64_p10_2 = {{(limb_t *)Pp_d64_p10_2_limbs, 9, 0}};
static const limb_t Pp_d64_p10_3_limbs[] = {8035370403536886273UL, 5262365139376202660UL, 16577153914975625676UL, 16194496132039856474UL, 14990983624558120198UL, 3706241500669197857UL, 856981974581477UL, 4503599626676264UL, 0UL};
static const int_t Pp_d64_p10_3 = {{(limb_t *)Pp_d64_p10_3_limbs, 9, 0}};
static const limb_t Pp_d64_p10_4_limbs[] = {12697982404528955137UL, 3366921202895450838UL, 1875975210431205004UL, 17996301083941752701UL, 1211312850226728075UL, 5892225188014985234UL, 843904554140646UL, 4503599626681384UL, 0UL};
static const int_t Pp_d64_p10_4 = {{(limb_t *)Pp_d64_p10_4_limbs, 9, 0}};
static const limb_t Pp_d64_p10_5_limbs[] = {15649869319426336769UL, 14128154769798961967UL, 13359663581444302980UL, 9571969081440049121UL, 8283728401516605691UL, 7354294509749399613UL, 820906363226381UL, 4503599626690600UL, 0UL};
static const int_t Pp_d64_p10_5 = {{(limb_t *)Pp_d64_p10_5_limbs, 9, 0}};
static const limb_t Pp_d64_p10_6_limbs[] = {2817562247691301377UL, 3269034021402133108UL, 14497580199417336177UL, 2298810328861422941UL, 12274966046038334301UL, 18000902213933906491UL, 796168861552232UL, 4503599626700840UL, 0UL};
static const int_t Pp_d64_p10_6 = {{(limb_t *)Pp_d64_p10_6_limbs, 9, 0}};
static const limb_t Pp_d64_p10_7_limbs[] = {9560707862240441729UL, 3435785617861698482UL, 14241585259863972245UL, 15047252864081395673UL, 16369489324804681335UL, 12418302646724504352UL, 787713673170994UL, 4503599626704424UL, 0UL};
static const int_t Pp_d64_p10_7 = {{(limb_t *)Pp_d64_p10_7_limbs, 9, 0}};
static const limb_t Pp_d64_p10_8_limbs[] = {4448378075102313217UL, 13332499443780823995UL, 5681467650799578808UL, 16558115637019120123UL, 3034084248368341027UL, 7585853558091884442UL, 774639549453035UL, 4503599626710056UL, 0UL};
static const int_t Pp_d64_p10_8 = {{(limb_t *)Pp_d64_p10_8_limbs, 9, 0}};
static const limb_t Pp_d64_p10_9_limbs[] = {336329181040231553UL, 15867039822155453239UL, 15577786647126898074UL, 3365627165481086305UL, 2596928608176298840UL, 12314867309656356982UL, 752669004961632UL, 4503599626719784UL, 0UL};
static const int_t Pp_d64_p10_9 = {{(limb_t *)Pp_d64_p10_9_limbs, 9, 0}};
static const limb_t Pp_d64_p10_10_limbs[] = {12263297668384033025UL, 3802306618637875953UL, 18158156371391781627UL, 10197921094918803016UL, 5135392244264989569UL, 17770881784860906014UL, 742532487879010UL, 4503599626724392UL, 0UL};
static const int_t Pp_d64_p10_10 = {{(limb_t *)Pp_d64_p10_10_limbs, 9, 0}};
static const int_srcptr Pp_d64_p10[] = {Pp_d64_p10_0, Pp_d64_p10_1, Pp_d64_p10_2, Pp_d64_p10_3, Pp_d64_p10_4, Pp_d64_p10_5, Pp_d64_p10_6, Pp_d64_p10_7, Pp_d64_p10_8, Pp_d64_p10_9, Pp_d64_p10_10};
static const modulus_t d64_p10 = {{roots_d64_p10, 1125899906814209, 2009071762014301953, -560613217292737, -17592186043972, -359771454242051, P_d64_p10, Pp_d64_p10, k_d64_p10, 549}};


static const modulus_srcptr moduli_d64[] = {d64_p0, d64_p1, d64_p2, d64_p3, d64_p4, d64_p5, d64_p6, d64_p7, d64_p8, d64_p9, d64_p10};

/***********************************************************
 * degree 128 params
 */

#define NMODULI_D128 11
extern void *hexl_ntt_d128[];

static const crtcoeff_t roots_d128_p0[] = {29343744, -69174830805767, 48959125218339, 262485241596814, 412694376899749, 373927219197358, -70753781555832, 326412194788496, -396806682632790, 479719127649610, -509814162812394, 298275591901000, 554416974063345, 307703906411447, 59590449692171, 275285106938447, 548594139073435, -530395348501616, -461186107910784, 45147654470009, 73666197397104, 512321385516482, 298405660349717, 188894348288714, 170994764334521, -388147811785993, 493226774471532, -539613053681350, -312317357853293, 469164353125933, 65052930403110, -47514311282824, -338631562875440, -348786040326901, 215554776167931, 290740504661501, 471244635595924, -353610093688397, 357215168468612, 395700715951085, -468332895728365, -286731904201405, 110930914875246, -349703594188995, 431490514214663, -345395901411206, 411067679299929, -18034288803017, 173493646004075, -478567688637399, 239738563260274, 46195127494350, 177091583517774, -237852141494477, 33599907647133, 181765140212182, 519257143437216, 228244061030462, 339154796896709, 300990119183097, 248159931617846, -186735649070088, 235893542728171, -92385006320962, -559276658003835, 393027733698884, 410993836887979, -445969397098859, 363676859553830, -324924582989129, -519165710884057, -82198106770938, 545477036892141, 137781153038850, -544249343917789, 213342270488674, -190111442586377, 266006333897693, 556211772116129, 224804019526743, -248943593019960, -455902572850387, -144425222377985, 499802686744220, -366967495173680, 166161340080117, 218709244750109, -494368283075120, -189718206185022, 188605500135033, -285304437615420, 425736700565911, 227401469920811, -503692184863825, -191383087967508, -491763772708908, 107131664315732, -270738603938863, -437735476134342, 439322581912998, 546727625345114, -74583929469744, -483594522243281, -156429354759010, -547756539451963, -107248251836791, -21939079783489, -56450355509273, -104897123662423, -136010964354251, 122435801124729, -439319982833113, -512778912147281, 201429418558387, -206001650154403, -482929682978086, -88812300661185, -299647174739738, 173757630996770, 336611365370004, -40767596044264, -547083565697992, 452184071268702, 464642126819745, 90538695390396, 193582435271840, 536720034946694, -180258476257862};
static const crtcoeff_t k_d128_p0[] = {1};
static const limb_t P_d128_p0_limbs[] = {1125899906840833UL};
static const int_t P_d128_p0 = {{(limb_t *)P_d128_p0_limbs, 1, 0}};
static const limb_t Pp_d128_p0_0_limbs[] = {1UL};
static const int_t Pp_d128_p0_0 = {{(limb_t *)Pp_d128_p0_0_limbs, 1, 0}};
static const int_srcptr Pp_d128_p0[] = {Pp_d128_p0_0};
static const modulus_t d128_p0 = {{roots_d128_p0, 1125899906840833, -8444618314856986879, -264844594903297, -8796093022194, 1, P_d128_p0, Pp_d128_p0, k_d128_p0, 49}};

static const crtcoeff_t roots_d128_p1[] = {268419072, -336238421527800, 351238124101666, 316070935027490, -129052447448090, -366640851656903, 23436250045608, 85310602592841, 260196883219839, -10189598936231, 303292867306671, -541245131056016, 345585095177476, -102474663296033, 427277184855048, -114651964721787, 28992337726558, -434642355916687, -323642159343622, -501574242758521, 130050566527584, -450305034070214, 350201713474494, 527195248390931, -531492805401932, 135501529061437, 159364272337749, 1965358964196, -493800737215921, -116043516212397, -479685885065800, -313492556453604, 273599095618747, -463519892364654, -218861333051777, 282313902052128, 241637576748769, 450586655481540, -495556239835834, 520426635250560, -154705375835640, 313389532628126, 493563858157295, -362098807037778, -301172880624024, -536358837549500, 297047858853401, -375463138020318, 376279581489624, 44918735197600, 394346427065004, 482992094701910, -65869417934980, 339171894238510, -403802949706959, -460206249962657, 138582209724904, -295462926422117, -349021912768824, 501415728210637, -359909779473474, -305522679345582, 80094410492908, -268175139850141, 110469446921598, 162948989594188, 125989075304452, -95580247115197, 452087541067376, 283886246331217, -23445519593637, -225095061351202, -437322032411134, 516761866835226, -300546227379142, 316606759843240, -381395649191358, 535662636250529, 465282627716132, -322450397239498, -542272900536741, -18732025839534, 292150146898280, 449419228199841, -415190411131732, -252860202474829, -556644004163357, -498178813554041, -324436162030270, 446942418917653, 50735156047199, -510731725400990, 521204321942393, -159462905167844, 218224047991596, -459925453280879, -376792436907869, 523134801258408, -33245164587777, -333677846216259, 25596978280614, -302356264647920, -358667436876800, 290735094347331, 132370767059282, -213926612069191, -32263890902713, 398232022430281, -372089176469944, 119296635508655, -55485730805557, -117703848727539, 513345380585887, 142739347014235, 333994236431117, -236939734841273, -297256945115025, 538345617865377, -177111873758968, -206401135537621, -443514601210276, -401299404046713, 222215619874071, 188054032763263, -423637693248890, -168760879554864, 143972661426394, 122293591519247};
static const crtcoeff_t k_d128_p1[] = {77158710721, -77158710720};
static const limb_t P_d128_p1_limbs[] = {16431383240490596609UL, 68719476734UL};
static const int_t P_d128_p1 = {{(limb_t *)P_d128_p1_limbs, 2, 0}};
static const limb_t Pp_d128_p1_0_limbs[] = {1125899906826241UL, 0UL};
static const int_t Pp_d128_p1_0 = {{(limb_t *)Pp_d128_p1_0_limbs, 2, 0}};
static const limb_t Pp_d128_p1_1_limbs[] = {1125899906840833UL, 0UL};
static const int_t Pp_d128_p1_1 = {{(limb_t *)Pp_d128_p1_1_limbs, 2, 0}};
static const int_srcptr Pp_d128_p1[] = {Pp_d128_p1_0, Pp_d128_p1_1};
static const modulus_t d128_p1 = {{roots_d128_p1, 1125899906826241, 70936092446048257, -8795823538240, -8796093022080, -77158710720, P_d128_p1, Pp_d128_p1, k_d128_p1, 99}};

static const crtcoeff_t roots_d128_p2[] = {289390592, -30545265818544, -232960902161961, 357304586224328, -271858260766994, 439558361774467, 60267869704971, 531796335327750, 558012713630270, 308867119327935, -307658119318813, -243309196536556, 189880241623103, 378288500067609, -356307556618608, -238684687898840, 538519640568766, 209653088787894, 513547847663673, 389113137100374, -197892276336395, 231512652308618, 317200610181647, 453693669978612, 26474192830112, 502943058890287, 236432148937727, -395513436031733, 217649173378908, 140922551083065, 156212339503167, -323415996906497, 426554980048413, 279323213763523, 527715521224583, -420128980377385, 520732739459749, -183006659178044, -532245520071994, -502504696149440, -127107196866838, -470485246104427, 218845670829575, -105423245880765, -158968236198982, 459465270246211, 441332226082046, 335754408134486, -295677622571897, -120713895067542, -141336338705591, 490360329712776, -374999461221636, 506258429042222, 540261031086080, -481876382162354, 512588883678982, 432817459770358, 91516020889338, 123820431388453, 423755362099709, 499533145260287, -238710301949572, -162361270646285, 214747937544211, 498115593542824, 481290565253171, 327780061578422, 347707851279857, -328066281641072, 301299691180849, 525362171187990, 403951652893381, 445898317912506, 40049397739107, -423312933198357, 267904452558438, -249184739161199, 515154901965274, -485751481945562, 326632897940064, 142035597812203, -423741225142010, -249439415106136, -157855489922542, -362053627672015, -371975475528242, 205090758929990, -148931932795838, -426974621707763, 417954746954551, -95539036784642, 91718503395933, 155864546244680, 70634062034538, -57493023603339, -203440324574156, 277566857017571, 393974911718382, -98973445977890, 245246185564086, -63583393753188, 365157921101764, 365854748533019, -114739289210516, 471943973980202, -367381751137086, 213860774814667, -299084707747247, 204958710578860, -379046488743869, 311013835754490, -337126163464627, -330741682431216, -386574311270345, -57651744358156, 364923689578229, 459227308761807, -161279321887421, -417283933651284, -80088993885823, -301464416810635, -41362387851080, 454824309539570, -132573993138206, -339462592502970, 56946785571652, -351718253589492};
static const crtcoeff_t k_d128_p2[] = {-95267367190395, 281475036986803, -186207669797431};
static const limb_t P_d128_p2_limbs[] = {11532592227522081793UL, 18444281373821784967UL, 4194303UL};
static const int_t P_d128_p2 = {{(limb_t *)P_d128_p2_limbs, 3, 0}};
static const limb_t Pp_d128_p2_0_limbs[] = {17007843993054051073UL, 68719476733UL, 0UL};
static const int_t Pp_d128_p2_0 = {{(limb_t *)Pp_d128_p2_0_limbs, 3, 0}};
static const limb_t Pp_d128_p2_1_limbs[] = {14990231359734330369UL, 68719476734UL, 0UL};
static const int_t Pp_d128_p2_1 = {{(limb_t *)Pp_d128_p2_1_limbs, 3, 0}};
static const limb_t Pp_d128_p2_2_limbs[] = {16431383240490596609UL, 68719476734UL, 0UL};
static const int_t Pp_d128_p2_2 = {{(limb_t *)Pp_d128_p2_2_limbs, 3, 0}};
static const int_srcptr Pp_d128_p2[] = {Pp_d128_p2_0, Pp_d128_p2_1, Pp_d128_p2_2};
static const modulus_t d128_p2 = {{roots_d128_p2, 1125899906824961, 8941995416230642945, 430321633063350, -8796093022070, -186207669797431, P_d128_p2, Pp_d128_p2, k_d128_p2, 149}};

static const crtcoeff_t roots_d128_p3[] = {327139328, -360984481833569, 226313967773885, -46694848214382, -98142519694482, -69546835308817, -89006173110395, -554565270894748, 529589234250771, 521596007276002, 553096926914183, -216279266392088, -557051614707854, -541053536052130, 444136915744666, -142841865802716, 171792450769079, -190765478913316, -457015279520404, 407365767065455, 96769026476511, 512207928908281, 104168764093458, 409964567610915, 302222302417936, 545836590079215, -483695936082938, 416795642699652, 423935788977371, -160394332096776, 168196978411273, 43530363421598, 426397293116960, 436376762311200, -378600570501982, -3667315014973, 281499849452476, -11155246813906, 554029034654044, -157029538710847, 209220648272097, 374590900391041, -40086826354583, -372682027831351, 211907333747311, 18845719859225, 148005714528216, 210234390824230, -139495371280150, 372572936706744, -257466491732075, -256430137313246, 384621557500678, 124346218671498, 25033420818682, 466922950863064, 15276343620370, -9371127006114, -400331460688529, 42304029894270, 316485617413645, -402989257676073, -385450373891699, -292791592351427, 141438401444790, -314727120584806, -544423678266453, -25271866096213, -222333531618860, -305932576001722, -18461462564716, 99509885633259, 318622990844993, -431017836041028, 422489123553884, 127356475856337, -508867740306962, -547637867919180, 1604887049428, 426101990730742, 268925752882381, -238369992872961, -252211185983534, -338952816235991, -134986439299270, 383882252679987, 532475045451385, -451760505277681, 194472308026168, -21350606657170, -55653741913517, -551399581970556, 187297231246216, -36191552936128, 333914620841107, -397083051483659, 323991156864805, 335661705902063, 365440973465416, 324198170299588, 425426797682473, 452713131280325, 71029212070597, 108077671990837, -100875907293054, -147635571674481, -117196258106598, -100319758447257, -134363906998065, 546777843627983, 103206752819740, -559039142589118, 72569207311809, 213551251858995, 336520467129554, -374459890787154, 298261221445852, 524762497499838, 24924617987909, 222783934819939, -95140226433466, 236459772441676, 262590995088524, 329902159924320, 225420350136539, -123088120855134, 505359286812421, -183441838108894};
static const crtcoeff_t k_d128_p3[] = {87532561384974, 297417895292261, -151896121246860, -233054335428326};
static const limb_t P_d128_p3_limbs[] = {14426370642721515009UL, 17908318039492416589UL, 18446743839650611203UL, 255UL};
static const int_t P_d128_p3 = {{(limb_t *)P_d128_p3_limbs, 4, 0}};
static const limb_t Pp_d128_p3_0_limbs[] = {7497361701755759873UL, 18443032328612669201UL, 4194303UL, 0UL};
static const int_t Pp_d128_p3_0 = {{(limb_t *)Pp_d128_p3_0_limbs, 4, 0}};
static const limb_t Pp_d128_p3_1_limbs[] = {3462141581896345089UL, 18444035083217167399UL, 4194303UL, 0UL};
static const int_t Pp_d128_p3_1 = {{(limb_t *)Pp_d128_p3_1_limbs, 4, 0}};
static const limb_t Pp_d128_p3_2_limbs[] = {6344445389187410689UL, 18444123044147387779UL, 4194303UL, 0UL};
static const int_t Pp_d128_p3_2 = {{(limb_t *)Pp_d128_p3_2_limbs, 4, 0}};
static const limb_t Pp_d128_p3_3_limbs[] = {11532592227522081793UL, 18444281373821784967UL, 4194303UL, 0UL};
static const int_t Pp_d128_p3_3 = {{(limb_t *)Pp_d128_p3_3_limbs, 4, 0}};
static const int_srcptr Pp_d128_p3[] = {Pp_d128_p3_0, Pp_d128_p3_1, Pp_d128_p3_2, Pp_d128_p3_3};
static const modulus_t d128_p3 = {{roots_d128_p3, 1125899906822657, 6717599665002663425, 59648776139169, -8796093022052, -233054335428326, P_d128_p3, Pp_d128_p3, k_d128_p3, 199}};

static const crtcoeff_t roots_d128_p4[] = {369082368, 300489023163428, 119388681941738, 421347163950709, -231338438161156, 120059243719409, 360144383997281, -511062208936740, -172245187463572, 531119894792160, 75805070946510, 508465332023459, -124113795002142, -475066130675007, -305681270877881, -298848858017690, -289245256367522, -394266116964101, 165322140821889, 259314458597312, -17128898609526, -298101406446035, 371435563149069, 462871123139251, -479649956626004, 307465930108778, 503844164910008, -336209203777636, 548345646052417, 222379463637849, -326949571339385, 541321571801292, -306103769137724, -409622502713981, -135692932553300, 472763840709054, -221996364267934, -322682890348346, -101106193389107, -203189416493259, 194082559402853, -59259970337120, 532101726835202, -265139805421473, 57989963437028, 150742428584027, -150192653263894, -369806461529513, -366268854140503, -454654319837679, 406582504710993, 349551718119447, 224298276320353, 429029981745351, 532564250326929, 483344802919165, -439575341305099, -8008265510960, -71799573419153, -432659129568632, 318555014989876, 7118667122184, 477191977296355, -369755082248156, 322905112725899, 541143177045626, 126872012687573, 386060328862813, -411657884643538, 500095124751021, -24186066004462, -469510664188497, -443511350799023, 222906974716527, -280311966359020, 222240821881027, -223251854359928, -459167271827849, -451786231938078, -194305903220945, -348451669836869, 144928216637472, -226563890914758, 185514443806294, 166496828496057, 413094660591219, 99610217194582, 183350178168521, -274699311688731, 142401003909077, -141201657603206, -17099702272762, 181261121874051, -427570130161705, 219244732603240, 465897362693412, 511924132660100, -309713482632696, 248369596678340, 371405652994924, 193894596262902, -203206376488940, 316683164755960, -56541830497643, 153314883185222, 146485116716798, -238249866049365, 180944781082175, -102772878001264, 493880854303437, -313671862559726, -244226975534583, 431234697033220, 372597538540850, 45402240851477, -341787851560726, -395326887176532, 162473999124526, 539400812614686, -6032871946341, -146779309550376, -554275943276952, 551958219861804, 369831054408084, -529824409078853, 15310156536402, 82017143099595, -265177560662901};
static const crtcoeff_t k_d128_p4[] = {14655933752201, -122277450479882, 204656129472556, 124115948460710, -221150561204816};
static const limb_t P_d128_p4_limbs[] = {4392758147274100225UL, 15464598713872739748UL, 9743382460904766UL, 288230376131659008UL};
static const int_t P_d128_p4 = {{(limb_t *)P_d128_p4_limbs, 4, 0}};
static const limb_t Pp_d128_p4_0_limbs[] = {18293176259385808129UL, 2641343999898407521UL, 18446743752677523464UL, 255UL};
static const int_t Pp_d128_p4_0 = {{(limb_t *)Pp_d128_p4_0_limbs, 4, 0}};
static const limb_t Pp_d128_p4_1_limbs[] = {12124408458690301441UL, 16105611550991493068UL, 18446743813880807428UL, 255UL};
static const int_t Pp_d128_p4_1 = {{(limb_t *)Pp_d128_p4_1_limbs, 4, 0}};
static const limb_t Pp_d128_p4_2_limbs[] = {16446832951235777281UL, 12210261756147766468UL, 18446743819249516548UL, 255UL};
static const int_t Pp_d128_p4_2 = {{(limb_t *)Pp_d128_p4_2_limbs, 4, 0}};
static const limb_t Pp_d128_p4_3_limbs[] = {5780786121474710529UL, 5766085678465484813UL, 18446743828913192964UL, 255UL};
static const int_t Pp_d128_p4_3 = {{(limb_t *)Pp_d128_p4_3_limbs, 4, 0}};
static const limb_t Pp_d128_p4_4_limbs[] = {14426370642721515009UL, 17908318039492416589UL, 18446743839650611203UL, 255UL};
static const int_t Pp_d128_p4_4 = {{(limb_t *)Pp_d128_p4_4_limbs, 4, 0}};
static const int_srcptr Pp_d128_p4[] = {Pp_d128_p4_0, Pp_d128_p4_1, Pp_d128_p4_2, Pp_d128_p4_3, Pp_d128_p4_4};
static const modulus_t d128_p4 = {{roots_d128_p4, 1125899906820097, -3382455769235433471, -12094356744313, -8796093022032, -221150561204816, P_d128_p4, Pp_d128_p4, k_d128_p4, 249}};

static const crtcoeff_t roots_d128_p5[] = {406831104, -31993252316301, 540205155977758, 243824982313753, 378238621042086, 75177629376752, -88018990938654, 521085524439760, -15821159353624, 223858803733240, 543086189747840, -475720685282593, 522834070298570, -369643368578243, 308023817978837, 501585871538476, 50162635535330, -395387706048458, -48694002827933, 561747339512589, 343481816686194, -513390779336543, 245643917831978, -258143770158127, 161131935882137, 298168351307373, -483975133651927, -289737292000146, -298261484969274, -292807999500173, -554761412718974, -255864694258700, -295760299606679, -299000435390671, 419964247081855, -300834936503622, 361224042112583, 530409486814240, 299709136333259, 159067316435838, 154470338596066, 317208055430989, -263638435171730, 20267549184063, -292278345509312, 2413585233620, 548916002543152, 40405076055527, -416039373936446, -160191099274809, -62199100895427, -87111564874557, 214141676050845, -371334838006055, -19712332071189, 23946396708425, -265059273517200, 57673550149742, -160069765679810, 430198258961711, -291218540337143, -34094829307178, 94701187150906, 150261024173418, -297257426960693, 333999488222121, 322752402196589, -80780076458680, -335498649972198, 534956333569314, -362604263257981, 442590330904596, 299682113548411, 493362144304630, 523560750496583, -529390546995369, 438295277437440, 326484544830188, 540489369242632, -518069161955893, -5429924755918, -96232646506134, 93583748605449, -360506684856179, 270064907798456, 218099169652365, 556766172380732, -411703186376221, -493270269479782, -539773861011058, -249957716428190, 20977959168070, 188029947479990, -470463910923990, -428763042015709, -502856490230301, -298122482367299, 147726577872969, 264647941381918, 277496426981932, -472281831417300, 270076868439063, -301759267230629, 93588560684758, 440942615242613, 540793107003130, -525986865454665, 174515583991045, -389592700153121, 238102457221123, -414638081994404, -35593945744101, -36921703188516, -18313386526141, 242977059213968, 79105465048083, 508603938022985, 314293705407578, -299842246879820, -442484160138720, -154665765088555, -158762279568736, -509135397267846, -183680644550553, -494538043096679, -411917971361537, -550152717214240, -90801368521953};
static const crtcoeff_t k_d128_p5[] = {6694168025323, -35436446231688, -475645866907848, -376405708150103, -414297730217985, 169191676658877};
static const limb_t P_d128_p5_limbs[] = {3056504047426825473UL, 17576000861964407922UL, 13216702685961715536UL, 1729383349528628971UL, 17592186042804UL};
static const int_t P_d128_p5 = {{(limb_t *)P_d128_p5_limbs, 5, 0}};
static const limb_t Pp_d128_p5_0_limbs[] = {820338014090130433UL, 14707540222374214244UL, 17139960389523547UL, 288230376125760768UL, 0UL};
static const int_t Pp_d128_p5_0 = {{(limb_t *)Pp_d128_p5_0_limbs, 5, 0}};
static const limb_t Pp_d128_p5_1_limbs[] = {12159940440747650305UL, 18442503619392015347UL, 11938415691797614UL, 288230376129496320UL, 0UL};
static const int_t Pp_d128_p5_1 = {{(limb_t *)Pp_d128_p5_1_limbs, 5, 0}};
static const limb_t Pp_d128_p5_2_limbs[] = {6635538766966927873UL, 3662216324795557037UL, 11567351992267446UL, 288230376129824000UL, 0UL};
static const int_t Pp_d128_p5_2 = {{(limb_t *)Pp_d128_p5_2_limbs, 5, 0}};
static const limb_t Pp_d128_p5_3_limbs[] = {17933775701348301569UL, 8274850696273064111UL, 10934071949386574UL, 288230376130413824UL, 0UL};
static const int_t Pp_d128_p5_3 = {{(limb_t *)Pp_d128_p5_3_limbs, 5, 0}};
static const limb_t Pp_d128_p5_4_limbs[] = {7067618141515531521UL, 1619584537902330266UL, 10282654259614082UL, 288230376131069184UL, 0UL};
static const int_t Pp_d128_p5_4 = {{(limb_t *)Pp_d128_p5_4_limbs, 5, 0}};
static const limb_t Pp_d128_p5_5_limbs[] = {4392758147274100225UL, 15464598713872739748UL, 9743382460904766UL, 288230376131659008UL, 0UL};
static const int_t Pp_d128_p5_5 = {{(limb_t *)Pp_d128_p5_5_limbs, 5, 0}};
static const int_srcptr Pp_d128_p5[] = {Pp_d128_p5_0, Pp_d128_p5_1, Pp_d128_p5_2, Pp_d128_p5_3, Pp_d128_p5_4, Pp_d128_p5_5};
static const modulus_t d128_p5 = {{roots_d128_p5, 1125899906817793, -7715290210673532671, 4260879643245, -8796093022014, 169191676658877, P_d128_p5, Pp_d128_p5, k_d128_p5, 299}};

static const crtcoeff_t roots_d128_p6[] = {465551360, 445728664760104, 81978481825634, 354607522289887, -219232232835229, -351201501928606, -111981532800004, 357183757521746, -25714392066632, 28842499987492, -439728032982631, 308748781264927, -241068198288118, -137967918483773, 207785838302105, -185534010588194, 276264439351814, -159119695861151, -152099671452892, 361962063983329, 495262924298710, 272907757233251, -374379887621867, 227742775180933, -389940585649400, -67565752364918, 185783166671994, 381037213130125, -469462777080386, 118062025858268, 328966399879956, -183529216429884, -32953610891917, -484635225955876, -213078725074071, -134391376575862, -59929501491482, -320201174044276, 470556238969183, -47917716419036, 340853174114046, -410299517606348, -323641697851788, -146465470778702, 545165716044064, -222105094439148, 399604247791004, 451301116083191, 391623101695115, 548169506221673, 22486393413342, 43724543164066, -316657702679032, -53358894144314, 514440751400739, 70303744026815, -384756376648919, -228043157516132, -512677278208111, -154277594375932, 420696051656471, -285719337881248, 529828047088465, 519309149253831, 368900816400152, 546724439814067, -183486146441254, 468624487066237, -404090763928914, 252501128723308, -371787615259213, 43818948274757, -434177105143492, -372533379965551, 393845389600070, 202901123161339, -466630489842267, 306726807415023, -255782901790612, -259563002098632, -131881387346782, 410844739036866, 350463652421920, 502105470739756, 411836850924540, -412652743507618, 327449603887026, 527840841304118, 425829753297073, 74872907121685, 437227067905334, -517579879796954, 62533215607021, -442491625847415, 225758205919112, -262119582006544, 114007044340272, 277002356681816, 50946929801317, 479228635363158, 184446741819297, 10793388258812, -227151852121783, 190613669412071, -340929795087371, -214639272203068, 88104652442891, 54797754126202, -562600548919147, 53863338165964, 435863112407032, -259185147616074, -133163434891973, -438407862200098, -429361802717890, 258651306368823, -503897779803278, 533786405018735, 255334048050693, 348358958626560, -364001048497519, -162216758947786, -463353245212933, 322835929847558, 39982657552213, 13746740706940, 13052011166706, -490728452084066};
static const crtcoeff_t k_d128_p6[] = {-368970980369377, 107053268771231, 193558284382388, 159040600680348, 48831313513815, 461433529977310, 524953889855679};
static const limb_t P_d128_p6_limbs[] = {9680084218057063937UL, 10977705560365750715UL, 4458689420968925938UL, 5998953933998802224UL, 16132017010655918032UL, 1073741823UL};
static const int_t P_d128_p6 = {{(limb_t *)P_d128_p6_limbs, 6, 0}};
static const limb_t Pp_d128_p6_0_limbs[] = {3322200183903290625UL, 13061573003536527314UL, 18050999118025569381UL, 1729384040447413970UL, 17592186042388UL, 0UL};
static const int_t Pp_d128_p6_0 = {{(limb_t *)Pp_d128_p6_0_limbs, 6, 0}};
static const limb_t Pp_d128_p6_1_limbs[] = {14227113635861773825UL, 13256914989432133750UL, 17147637671929224787UL, 1729383616824610531UL, 17592186042616UL, 0UL};
static const int_t Pp_d128_p6_1 = {{(limb_t *)Pp_d128_p6_1_limbs, 6, 0}};
static const limb_t Pp_d128_p6_2_limbs[] = {9749758727563985665UL, 6777929956318290774UL, 17971742581068995322UL, 1729383584865652452UL, 17592186042636UL, 0UL};
static const int_t Pp_d128_p6_2 = {{(limb_t *)Pp_d128_p6_2_limbs, 6, 0}};
static const limb_t Pp_d128_p6_3_limbs[] = {1628456433522592769UL, 6350614032609863005UL, 13079383226091692675UL, 1729383529453457126UL, 17592186042672UL, 0UL};
static const int_t Pp_d128_p6_3 = {{(limb_t *)Pp_d128_p6_3_limbs, 6, 0}};
static const limb_t Pp_d128_p6_4_limbs[] = {4775517092725675521UL, 18428927800881984930UL, 8012666626482655051UL, 1729383471072022248UL, 17592186042712UL, 0UL};
static const int_t Pp_d128_p6_4 = {{(limb_t *)Pp_d128_p6_4_limbs, 6, 0}};
static const limb_t Pp_d128_p6_5_limbs[] = {12930743165008699137UL, 6473407765558204700UL, 15189908093498134420UL, 1729383421397634793UL, 17592186042748UL, 0UL};
static const int_t Pp_d128_p6_5 = {{(limb_t *)Pp_d128_p6_5_limbs, 6, 0}};
static const limb_t Pp_d128_p6_6_limbs[] = {3056504047426825473UL, 17576000861964407922UL, 13216702685961715536UL, 1729383349528628971UL, 17592186042804UL, 0UL};
static const int_t Pp_d128_p6_6 = {{(limb_t *)Pp_d128_p6_6_limbs, 6, 0}};
static const int_srcptr Pp_d128_p6[] = {Pp_d128_p6_0, Pp_d128_p6_1, Pp_d128_p6_2, Pp_d128_p6_3, Pp_d128_p6_4, Pp_d128_p6_5, Pp_d128_p6_6};
static const modulus_t d128_p6 = {{roots_d128_p6, 1125899906814209, 2009071762014301953, -560613217292737, -8796093021986, 524953889855679, P_d128_p6, Pp_d128_p6, k_d128_p6, 349}};

static const crtcoeff_t roots_d128_p7[] = {490717184, -415802113283121, -539739173836157, -115714837168270, -278450741829066, -417041023648345, -545899741875779, 447742257584984, 556837352019332, 149888967920830, 111726091492874, 471161850070731, -69605675122825, -16519546025583, 333094321412298, -64922460575653, 530464860754057, 48209198403639, 349629286849553, 476152336839713, -6420207209157, 59392499229350, 235513379190425, 443959328191402, 440538572278140, -398608763618226, -519892249018867, 92754634508775, -324604946756766, 17093423788218, -265996646894821, -338866604575760, 517868012189850, -18677579724991, 470493030734872, -537975146658116, -91150322129350, 147502385718011, -285171973678908, 177628506216724, 552722718509725, -29729229746895, 46851857010437, 99283667952132, 166876145206385, 348076514574078, 404646869695875, -100130085995477, -268240879811386, 229994314215951, -455763076002929, 109077397659012, -547685880017705, 298622471063666, 334748456293230, -137748659807650, -343515356803913, -475906543025426, 343770003837646, 81567667051805, -343609444749350, 252694769435141, 503773651598959, 152965791209290, -338398318440449, -499440066624134, -40974089274099, 55103010227498, 504996516466338, -323507258006286, 439679050286691, -315886189374408, -130315562177445, -532595805770525, -541522043350832, 107016565190588, 64693281205025, 443263066389276, -321015068833833, -548388412674321, 37202640153931, 68872633960715, -454262331650216, -452609214386771, -515124176021532, 141189346590867, -4129511733175, 1485234105565, 358322228476926, 170263304860062, -228197109712657, -511208553588378, -174733242265653, -471315430422601, 432187504052974, 434047609646654, 163155346229973, -360687725911078, 188005674292361, -372624683758305, 232940155587338, 202444007012056, 556845281426711, -524688464139156, 95897033178864, 103338441983516, 202511145296733, -479874267234710, 118442859971854, -53359307627883, -539335441035216, 145356261193317, -109961458124045, -365214817749706, -211155869258671, 272627112710009, 451421194443492, 447982865713012, 506864383266433, 209273011118496, 312860211202117, 403626370647881, 341115921931370, -316818151470154, 330693969046035, 530388830501918, 387946378450784, 219084118459276};
static const crtcoeff_t k_d128_p7[] = {257138894597790, -305464667622064, 110301914838287, 190791626777169, 52011696757244, 217613178558523, 327312698213604, 276194564699545};
static const limb_t P_d128_p7_limbs[] = {17145600687213742337UL, 8924024796273449461UL, 1540629726517925131UL, 16560212019709356925UL, 3166516461233049980UL, 18446570634340215168UL, 65535UL};
static const int_t P_d128_p7 = {{(limb_t *)P_d128_p7_limbs, 7, 0}};
static const limb_t Pp_d128_p7_0_limbs[] = {18408847356238860289UL, 6712011666506254827UL, 6803220961339467535UL, 5948729528037645708UL, 15636621051702269312UL, 1073741823UL, 0UL};
static const int_t Pp_d128_p7_0 = {{(limb_t *)Pp_d128_p7_0_limbs, 7, 0}};
static const limb_t Pp_d128_p7_1_limbs[] = {2932260142257916161UL, 15356591687012827867UL, 14093758383821538779UL, 5980502616232760555UL, 15893326230429702872UL, 1073741823UL, 0UL};
static const int_t Pp_d128_p7_1 = {{(limb_t *)Pp_d128_p7_1_limbs, 7, 0}};
static const limb_t Pp_d128_p7_2_limbs[] = {16247598655338958337UL, 10823895119834259548UL, 12105903695906351439UL, 5982636018264921708UL, 15915844228564005712UL, 1073741823UL, 0UL};
static const int_t Pp_d128_p7_2 = {{(limb_t *)Pp_d128_p7_2_limbs, 7, 0}};
static const limb_t Pp_d128_p7_3_limbs[] = {2752580866605831937UL, 7906585323222412106UL, 4397857911425144965UL, 5986248862823161737UL, 15956376625205879848UL, 1073741823UL, 0UL};
static const int_t Pp_d128_p7_3 = {{(limb_t *)Pp_d128_p7_3_limbs, 7, 0}};
static const limb_t Pp_d128_p7_4_limbs[] = {10883297492400201985UL, 14118506516253964345UL, 9171292127041781497UL, 5989939997153554583UL, 16001412621474823448UL, 1073741823UL, 0UL};
static const int_t Pp_d128_p7_4 = {{(limb_t *)Pp_d128_p7_4_limbs, 7, 0}};
static const limb_t Pp_d128_p7_5_limbs[] = {9639559917098232321UL, 15929046358421937078UL, 3602265469990306797UL, 5992991758693433528UL, 16041945018117047792UL, 1073741823UL, 0UL};
static const int_t Pp_d128_p7_5 = {{(limb_t *)Pp_d128_p7_5_limbs, 7, 0}};
static const limb_t Pp_d128_p7_6_limbs[] = {362862092679247873UL, 1826961420109196477UL, 13468588937990190395UL, 5997275672200134371UL, 16104995412894170944UL, 1073741823UL, 0UL};
static const int_t Pp_d128_p7_6 = {{(limb_t *)Pp_d128_p7_6_limbs, 7, 0}};
static const limb_t Pp_d128_p7_7_limbs[] = {9680084218057063937UL, 10977705560365750715UL, 4458689420968925938UL, 5998953933998802224UL, 16132017010655918032UL, 1073741823UL, 0UL};
static const int_t Pp_d128_p7_7 = {{(limb_t *)Pp_d128_p7_7_limbs, 7, 0}};
static const int_srcptr Pp_d128_p7[] = {Pp_d128_p7_0, Pp_d128_p7_1, Pp_d128_p7_2, Pp_d128_p7_3, Pp_d128_p7_4, Pp_d128_p7_5, Pp_d128_p7_6, Pp_d128_p7_7};
static const modulus_t d128_p7 = {{roots_d128_p7, 1125899906812673, 7229914168910509313, -139225385022166, -8796093021974, 276194564699545, P_d128_p7, Pp_d128_p7, k_d128_p7, 399}};

static const crtcoeff_t roots_d128_p8[] = {654295040, -248890341337064, 477473897671214, 223128209824878, -351375621231578, -192978995310695, -116318679158249, 340039841234370, -198431412767205, -62732518984457, -243282666657564, -8574139028120, -532784219354227, 525605620708766, -184554895524091, -364059970550902, -8189869486922, 451920041646634, 460192123057260, -228657687494038, -35035039532466, -165756820390831, 348608143762465, -99033139110946, -477042004037865, 314416563169231, 522497109218341, -336692166947947, -277802952124340, -350207388447907, -419763890923155, 163330747742242, -414619648107874, -246975168506905, 2899014936588, -363066444691181, 309790159300645, 371871826279598, -84344750897903, 180118319790578, 183064099666235, 247561041866042, 538691502531223, -353726073142540, 306547642525234, 545890318332950, 52698114136028, -470102345794730, -322694557750477, 492020416872442, 103270320779845, -77790282247611, -5355886056099, 296171538090761, -555968264592611, -426477340160338, 135073852315213, -451207618619903, -15348770071243, 48407010463463, 296938378727919, -448706295366105, 56835424718752, 475876479702705, 124815261951471, 393500192104164, 299272503732685, -164379163899675, -275473358989198, 149983733571990, 297828717643966, -36489945506463, -186158023574187, -535183405488157, 85495777052332, -495780237705086, -19895628413134, -522900578843321, 291026652861649, 294337436858162, -85018019769849, -371279082087000, 44895889609718, 214540670649530, -195145632323398, 258005549919388, -240074475351914, -524331025898807, 409923382428305, -486429952645207, -323868889720979, -188764071701348, 329945274356044, 540003952710555, 67350873205883, 386565517979576, 171073917005434, -520030358512644, 433793943306876, 514846576587564, 19767574183594, 499236809920253, -324872075301625, 159074572735347, -97899781670117, 184138637655200, 28578610890908, 166856943838356, -312071701901838, -362029425861004, 175284040190342, 429473266631831, -555145570659689, 402476489353664, -515491062209500, -371116618793229, -362020823482769, -371675560280019, -368619612196290, -397009456497405, -187071077743110, -401961881699512, 192496434111427, -320513367013161, 133253096920890, 370632494733068, 341353998051266, 383225664563833};
static const crtcoeff_t k_d128_p8[] = {359806594103795, 358740589567414, 401936056809017, 4557647276936, 562688256987482, 424210722756985, 97315016882703, -358073757882105, 400618687143088};
static const limb_t P_d128_p8_limbs[] = {17725027429318454529UL, 17647916253719139644UL, 909124805423548467UL, 14689517163421196414UL, 2636284675281081641UL, 441311019864509341UL, 18446744060506472449UL, 3UL};
static const int_t P_d128_p8 = {{(limb_t *)P_d128_p8_limbs, 8, 0}};
static const limb_t Pp_d128_p8_0_limbs[] = {5385210066209141761UL, 8312016596556168772UL, 8275909339840390100UL, 3173201179236333705UL, 16915999654514352496UL, 18446529677532086322UL, 65535UL, 0UL};
static const int_t Pp_d128_p8_0 = {{(limb_t *)Pp_d128_p8_0_limbs, 8, 0}};
static const limb_t Pp_d128_p8_1_limbs[] = {2717798123624017153UL, 15787665493330057046UL, 14502780365017912436UL, 4653597278159335730UL, 4877881095092392873UL, 18446545345572779580UL, 65535UL, 0UL};
static const int_t Pp_d128_p8_1 = {{(limb_t *)Pp_d128_p8_1_limbs, 8, 0}};
static const limb_t Pp_d128_p8_2_limbs[] = {1960098864498160129UL, 1183471084065294677UL, 14911639912774633727UL, 12123257627464384100UL, 16564722360151229765UL, 18446546719962314095UL, 65535UL, 0UL};
static const int_t Pp_d128_p8_2 = {{(limb_t *)Pp_d128_p8_2_limbs, 8, 0}};
static const limb_t Pp_d128_p8_3_limbs[] = {6461451882715888385UL, 15910817571200795218UL, 10062389320398499228UL, 18044516804710259428UL, 16848449535309301804UL, 18446549193863476231UL, 65535UL, 0UL};
static const int_t Pp_d128_p8_3 = {{(limb_t *)Pp_d128_p8_3_limbs, 8, 0}};
static const limb_t Pp_d128_p8_4_limbs[] = {8764489981592683777UL, 18380627953327853015UL, 4257240139354848511UL, 4682246177016901038UL, 14857858915445414760UL, 18446551942642545283UL, 65535UL, 0UL};
static const int_t Pp_d128_p8_4 = {{(limb_t *)Pp_d128_p8_4_limbs, 8, 0}};
static const limb_t Pp_d128_p8_5_limbs[] = {2936842551294119425UL, 17490780585017542945UL, 10817988436101317400UL, 16585858406859126775UL, 3612370996303670865UL, 18446554416543707441UL, 65535UL, 0UL};
static const int_t Pp_d128_p8_5 = {{(limb_t *)Pp_d128_p8_5_limbs, 8, 0}};
static const limb_t Pp_d128_p8_6_limbs[] = {5938453680636910593UL, 10063453240928428051UL, 17407212124272767382UL, 11001024316432196513UL, 10971253291053925083UL, 18446558264834404150UL, 65535UL, 0UL};
static const int_t Pp_d128_p8_6 = {{(limb_t *)Pp_d128_p8_6_limbs, 8, 0}};
static const limb_t Pp_d128_p8_7_limbs[] = {13676969769828311553UL, 18064996086774007934UL, 16425644707618955221UL, 1135398236872495631UL, 18077933704352126158UL, 18446559914101845604UL, 65535UL, 0UL};
static const int_t Pp_d128_p8_7 = {{(limb_t *)Pp_d128_p8_7_limbs, 8, 0}};
static const limb_t Pp_d128_p8_8_limbs[] = {17145600687213742337UL, 8924024796273449461UL, 1540629726517925131UL, 16560212019709356925UL, 3166516461233049980UL, 18446570634340215168UL, 65535UL, 0UL};
static const int_t Pp_d128_p8_8 = {{(limb_t *)Pp_d128_p8_8_limbs, 8, 0}};
static const int_srcptr Pp_d128_p8[] = {Pp_d128_p8_0, Pp_d128_p8_1, Pp_d128_p8_2, Pp_d128_p8_3, Pp_d128_p8_4, Pp_d128_p8_5, Pp_d128_p8_6, Pp_d128_p8_7, Pp_d128_p8_8};
static const modulus_t d128_p8 = {{roots_d128_p8, 1125899906802689, 3198992720342326273, 260034783579780, -8796093021896, 400618687143088, P_d128_p8, Pp_d128_p8, k_d128_p8, 449}};

static const crtcoeff_t roots_d128_p9[] = {843038720, -13406137695684, -370579912355579, -322249014670425, 401067968941038, 363064025777358, 240597923544521, -112499623666641, -562453842702916, -290103012757320, -473116427925385, 352825583823742, 357603065871740, 477048114694709, 291839723409659, 44295677383273, 231570193176622, -147104114455456, -323501777145152, 372800347903313, -312156778326679, -37406738942388, -198529458993625, 9061015667148, -68438632041314, 313600766568550, 188492266078129, 417863306905066, 122563645518166, -451934781485421, 75359743813347, 13312980276239, 210187653255274, -97343017042133, 94455655934302, -1114978390134, 560964387284370, -244010619147846, -491203146078795, -497304081299883, -384484487849772, -360572002609950, 431446183675222, -286784280784894, -335037143090628, -88848732589796, -362327427824858, 197724319528192, 476864247371021, -482833266569211, 413523644118467, 365091620052816, -20155308103501, -10559129972659, 132152177679751, 232561101261153, -122512127997879, -418081700771912, 497969971961478, 286849702386426, -106183686010988, 208028451160305, -430118339719549, -165862383014855, 162188897833340, 433118529502965, -487727777408422, 532590586143094, -440448611399822, 273704515218968, -529295376911719, 305508142016960, 464420417840791, 317568600038781, -239703724668583, -377706776483130, 502067355128579, 524380250315562, 271328344679793, 141200790250447, -518205490140279, -44611932422764, 511475461619652, 106783040337059, -512831412300131, -301586562817843, 139093393574665, 185765307709338, -393558813239354, 129109003235014, -78927327758130, -196120743356973, 523832687705048, 507028917064306, 70901833832407, 298265982961218, 522892532247784, 559692107728198, -267878155015292, -209487869657099, 6551426037653, 330146410330626, -156209143135345, 558961491448858, -255932859482412, 25792443919211, 184124156763396, 225244821003733, -307260987633846, -148557152427998, 170109259491936, -372650676221633, 77248486208999, 448354925627181, -220451146650917, 229182919609816, 483289237817667, -540608062181017, 307669826800675, 473736079322118, -144654398870922, 343822262095287, 492001009369376, 415075562093888, 332797379012882, -503896745298742, -281323748857310, 436470756245790};
static const crtcoeff_t k_d128_p9[] = {-435572541815541, 96233154085182, 163948612258192, 114706629301315, -305391778110048, -319677794709978, -36801212884027, -214073969735823, -208013508712089, 18742503501185};
static const limb_t P_d128_p9_limbs[] = {15605609593307079681UL, 10461155125182157421UL, 4290448906525179902UL, 15598067324907476903UL, 13427847844328506111UL, 3630888937220087200UL, 1832199832431655UL, 4503599626358824UL};
static const int_t P_d128_p9 = {{(limb_t *)P_d128_p9_limbs, 8, 0}};
static const limb_t Pp_d128_p9_0_limbs[] = {7547879859581364993UL, 10894546360499295386UL, 16499121368518707401UL, 11360773270843504500UL, 6494791828587959242UL, 11089082777500825014UL, 18446744057251692545UL, 3UL};
static const int_t Pp_d128_p9_0 = {{(limb_t *)Pp_d128_p9_0_limbs, 8, 0}};
static const limb_t Pp_d128_p9_1_limbs[] = {13435864545042064385UL, 10113850647859723021UL, 9917251364374822643UL, 2070597667601593032UL, 695057177259917722UL, 7411104232733346659UL, 18446744058207993857UL, 3UL};
static const int_t Pp_d128_p9_1 = {{(limb_t *)Pp_d128_p9_1_limbs, 8, 0}};
static const limb_t Pp_d128_p9_2_limbs[] = {5875422924781676801UL, 18334195321589314358UL, 16481053848822137787UL, 10860158828675950025UL, 13987207161268628073UL, 7110288846514788628UL, 18446744058291879937UL, 3UL};
static const int_t Pp_d128_p9_2 = {{(limb_t *)Pp_d128_p9_2_limbs, 8, 0}};
static const limb_t Pp_d128_p9_3_limbs[] = {8668533414069760513UL, 12946532160791643175UL, 16117158206447938076UL, 7108584774671634789UL, 7016876742690322648UL, 6577687613086203461UL, 18446744058442874881UL, 3UL};
static const int_t Pp_d128_p9_3 = {{(limb_t *)Pp_d128_p9_3_limbs, 8, 0}};
static const limb_t Pp_d128_p9_4_limbs[] = {10609388980239563777UL, 11793662989702887564UL, 16376553707041933467UL, 2667097594035927145UL, 3630496102875549819UL, 5999278526223687065UL, 18446744058610647041UL, 3UL};
static const int_t Pp_d128_p9_4 = {{(limb_t *)Pp_d128_p9_4_limbs, 8, 0}};
static const limb_t Pp_d128_p9_5_limbs[] = {4530326155762631937UL, 12713017470576762030UL, 10246968944887997847UL, 10954929405276507008UL, 8194479407950073767UL, 5490743403299819327UL, 18446744058761641985UL, 3UL};
static const int_t Pp_d128_p9_5 = {{(limb_t *)Pp_d128_p9_5_limbs, 8, 0}};
static const limb_t Pp_d128_p9_6_limbs[] = {15253020258642727681UL, 12811507718091098691UL, 7851432153934289690UL, 9352839334852718992UL, 694500834832949629UL, 4722347503262112278UL, 18446744058996523009UL, 3UL};
static const int_t Pp_d128_p9_6 = {{(limb_t *)Pp_d128_p9_6_limbs, 8, 0}};
static const limb_t Pp_d128_p9_7_limbs[] = {4607864192688232705UL, 17955514514899992309UL, 2100855557904798192UL, 4128240975011916210UL, 1434515642250934270UL, 4401479223974570315UL, 18446744059097186305UL, 3UL};
static const int_t Pp_d128_p9_7 = {{(limb_t *)Pp_d128_p9_7_limbs, 8, 0}};
static const limb_t Pp_d128_p9_8_limbs[] = {9693907935175884801UL, 16586985966912494185UL, 17069218301224239982UL, 17274260415812232123UL, 12026429068038398147UL, 2439332554620388323UL, 18446744059751497729UL, 3UL};
static const int_t Pp_d128_p9_8 = {{(limb_t *)Pp_d128_p9_8_limbs, 8, 0}};
static const limb_t Pp_d128_p9_9_limbs[] = {17725027429318454529UL, 17647916253719139644UL, 909124805423548467UL, 14689517163421196414UL, 2636284675281081641UL, 441311019864509341UL, 18446744060506472449UL, 3UL};
static const int_t Pp_d128_p9_9 = {{(limb_t *)Pp_d128_p9_9_limbs, 8, 0}};
static const int_srcptr Pp_d128_p9[] = {Pp_d128_p9_0, Pp_d128_p9_1, Pp_d128_p9_2, Pp_d128_p9_3, Pp_d128_p9_4, Pp_d128_p9_5, Pp_d128_p9_6, Pp_d128_p9_7, Pp_d128_p9_8, Pp_d128_p9_9};
static const modulus_t d128_p9 = {{roots_d128_p9, 1125899906791169, 8383988963308849409, 271442234010761, -8796093021806, 18742503501185, P_d128_p9, Pp_d128_p9, k_d128_p9, 499}};

static const crtcoeff_t roots_d128_p10[] = {868204544, -487937506020282, -157859842889590, -464444620575787, -560620299579660, -370164834755175, 235583976890432, -247885525958149, 369822370609003, 225879923751090, 148507429985286, 408740368358286, 206368381624626, 320889063738916, -488954702799935, 52556399089548, -68154480987933, -241412255943068, -280125501897252, -79832989405031, -205213764200694, 89947918198500, -188347878730296, 318719363304125, 47495807113165, 346253277184924, -325681167192581, -475750717957300, -39931137863571, 509821808334089, 35921388268960, -253666910001121, -225290636513113, 94971325076578, 416123740511319, 486974563551151, 532335981088248, 512077118695094, -209722557457972, -418541903286394, -67240331475761, -488385279231239, -146433918913309, -365394616970780, -197954131422064, 116860170887300, -122404728598560, -490284991768309, -330074554685441, -379986578692119, -454621489889256, 540455267289396, 280429254132803, -68988238367461, 145912245340764, -475551965216124, 407261793365370, -269984908840950, -209684709600319, -434693082253030, 562638695302234, -332781933775425, 330226432829541, -170175764706310, -216268961147236, 206152648276381, -110788336647702, 516330805135489, -281967339780022, 174484286715644, -310536245650536, -100529761645837, -473547997399734, -176986886202288, 123991779961494, -262662075345003, -429776394914210, -327813636905550, -330661421537327, 398367056866126, 127040871009953, 362830710359800, 61243322520121, -377329409393334, 427451642819235, -435290265523906, -397699495468998, 462174498377164, 383770348776283, 544539958599679, -366705323058621, 262891134327719, -24390771242861, -376193913053026, -261755983390375, 15926814647794, -521672601768021, 49357052367582, -413887153458218, 502552732713078, -481779749333984, 380644106496300, -5801512020663, 103379725349864, 229806398484454, 504022916588488, -283456481124430, -541548612801512, 50341709343776, -36735106395464, 15227621929234, -260198801650616, -544219285261747, 443417865161012, 540776995070379, -225219713585648, -159595715820301, 409740016429384, 500916654970602, -138407451235894, -164793156806939, 341806210613509, -285607907152696, -235269989988924, 18944695905125, -540476942887556, 497721236180143, 119372046574896};
static const crtcoeff_t k_d128_p10[] = {11509398902726, -202804857374517, -150430579393854, 351397033460266, -504989198234365, -39411137440612, 454695368503577, 205691266568762, 185510011721913, -280754171096692, -30413135616435};
static const limb_t P_d128_p10_limbs[] = {2609540831398483201UL, 1346742869428232780UL, 941089492839386000UL, 11340426409631711256UL, 10485297719401329130UL, 3644661025268241338UL, 7869887307077706241UL, 5814147284373424336UL, 274877906869UL};
static const int_t P_d128_p10 = {{(limb_t *)P_d128_p10_limbs, 9, 0}};
static const limb_t Pp_d128_p10_0_limbs[] = {4998399168816241665UL, 2334798390680137880UL, 17921236277622473184UL, 6740732347058586820UL, 1094896829192714195UL, 14928525601268541238UL, 2674842216836076UL, 4503599626154024UL, 0UL};
static const int_t Pp_d128_p10_0 = {{(limb_t *)Pp_d128_p10_0_limbs, 9, 0}};
static const limb_t Pp_d128_p10_1_limbs[] = {1013582011188811009UL, 7216941700852262726UL, 3922616550703199383UL, 12830050638337331910UL, 6834780358732213490UL, 12638973154950761277UL, 2399680858858419UL, 4503599626212392UL, 0UL};
static const int_t Pp_d128_p10_1 = {{(limb_t *)Pp_d128_p10_1_limbs, 9, 0}};
static const limb_t Pp_d128_p10_2_limbs[] = {11428840286103837185UL, 2086750107660847737UL, 14650020286328613078UL, 3290212872199471707UL, 6306757003995060161UL, 660570965731765501UL, 2376875337493750UL, 4503599626217512UL, 0UL};
static const int_t Pp_d128_p10_2 = {{(limb_t *)Pp_d128_p10_2_limbs, 9, 0}};
static const limb_t Pp_d128_p10_3_limbs[] = {2532679178357875457UL, 4370473508235734735UL, 13611341985220462965UL, 14959550596594041329UL, 16089351178500766025UL, 10933366382116808590UL, 2336366564916519UL, 4503599626226728UL, 0UL};
static const int_t Pp_d128_p10_3 = {{(limb_t *)Pp_d128_p10_3_limbs, 9, 0}};
static const limb_t Pp_d128_p10_4_limbs[] = {16582631040290041089UL, 15546160457352215036UL, 1151791055887476457UL, 4597863231288221442UL, 2225291732340753611UL, 11950148373054744373UL, 2292172861394547UL, 4503599626236968UL, 0UL};
static const int_t Pp_d128_p10_4 = {{(limb_t *)Pp_d128_p10_4_limbs, 9, 0}};
static const limb_t Pp_d128_p10_5_limbs[] = {856333019141158401UL, 7851422164831597418UL, 12062505899021718063UL, 9687159383301790348UL, 7209338003032375212UL, 4905477847769471683UL, 2253132967632233UL, 4503599626246184UL, 0UL};
static const int_t Pp_d128_p10_5 = {{(limb_t *)Pp_d128_p10_5_limbs, 9, 0}};
static const limb_t Pp_d128_p10_6_limbs[] = {13666055041429980161UL, 3875325392967688972UL, 436844819331644754UL, 6649732405498654411UL, 8613599171093656147UL, 14132360548047510019UL, 2193787223470995UL, 4503599626260520UL, 0UL};
static const int_t Pp_d128_p10_6 = {{(limb_t *)Pp_d128_p10_6_limbs, 9, 0}};
static const limb_t Pp_d128_p10_7_limbs[] = {11426754254895106561UL, 2089328839763892722UL, 4834844193838254180UL, 12338447096806127975UL, 306086396609864411UL, 13748485818234812577UL, 2168868729191597UL, 4503599626266664UL, 0UL};
static const int_t Pp_d128_p10_7 = {{(limb_t *)Pp_d128_p10_7_limbs, 9, 0}};
static const limb_t Pp_d128_p10_8_limbs[] = {15054697658188755201UL, 15547796465794043040UL, 3691462607941036066UL, 12747123653382924150UL, 15055490950705642045UL, 13232071109825774432UL, 2014436183978600UL, 4503599626306600UL, 0UL};
static const int_t Pp_d128_p10_8 = {{(limb_t *)Pp_d128_p10_8_limbs, 9, 0}};
static const limb_t Pp_d128_p10_9_limbs[] = {17357730955459108353UL, 1528833691914986665UL, 9827297377880655937UL, 12867706456731411291UL, 3931538754978908216UL, 8306693152587148997UL, 1852479762032130UL, 4503599626352680UL, 0UL};
static const int_t Pp_d128_p10_9 = {{(limb_t *)Pp_d128_p10_9_limbs, 9, 0}};
static const limb_t Pp_d128_p10_10_limbs[] = {15605609593307079681UL, 10461155125182157421UL, 4290448906525179902UL, 15598067324907476903UL, 13427847844328506111UL, 3630888937220087200UL, 1832199832431655UL, 4503599626358824UL, 0UL};
static const int_t Pp_d128_p10_10 = {{(limb_t *)Pp_d128_p10_10_limbs, 9, 0}};
static const int_srcptr Pp_d128_p10[] = {Pp_d128_p10_0, Pp_d128_p10_1, Pp_d128_p10_2, Pp_d128_p10_3, Pp_d128_p10_4, Pp_d128_p10_5, Pp_d128_p10_6, Pp_d128_p10_7, Pp_d128_p10_8, Pp_d128_p10_9, Pp_d128_p10_10};
static const modulus_t d128_p10 = {{roots_d128_p10, 1125899906789633, -7487435483381641471, 552092579983459, -8796093021794, -30413135616435, P_d128_p10, Pp_d128_p10, k_d128_p10, 549}};


static const modulus_srcptr moduli_d128[] = {d128_p0, d128_p1, d128_p2, d128_p3, d128_p4, d128_p5, d128_p6, d128_p7, d128_p8, d128_p9, d128_p10};

#endif

