#ifndef LNP_TBOX_H
#define LNP_TBOX_H
#include "lazer.h"
/*
 * Number of eqs and offsets in quadeqs R2[],r1[],r0[].
 * The first lambda/2 elements are reserved for the subprotocols.
 */
#define QUADEQ_BETA3_N (1)
#define QUADEQ_BETA4_N (1)

#define QUADEQ_BASE_OFF ((lambda) / 2)
#define QUADEQ_BETA3_OFF (QUADEQ_BASE_OFF)
#define QUADEQ_BETA4_OFF (QUADEQ_BETA3_OFF + QUADEQ_BETA3_N)
#define QUADEQ_INPUT_OFF (QUADEQ_BETA4_OFF + QUADEQ_BETA4_N)

/*
 * Number of eqs and offsets in evaleqs R2'[],r1'[],r0'[].
 */
#define EVALEQ_BETA3_N (d - 1)
#define EVALEQ_BETA4_N (d - 1)
#define EVALEQ_Z3_N (256)
#define EVALEQ_Z4_N (256)
#define EVALEQ_UPSILON_N (Z)
#define EVALEQ_BIN_N (1)
#define EVALEQ_L2_N (Z)

#define EVALEQ_BASE_OFF (0)
#define EVALEQ_BETA3_OFF (EVALEQ_BASE_OFF)
#define EVALEQ_BETA4_OFF (EVALEQ_BETA3_OFF + EVALEQ_BETA3_N)
#define EVALEQ_Z3_OFF (EVALEQ_BETA4_OFF + EVALEQ_BETA4_N)
#define EVALEQ_Z4_OFF (EVALEQ_Z3_OFF + EVALEQ_Z3_N)
#define EVALEQ_UPSILON_OFF (EVALEQ_Z4_OFF + EVALEQ_Z4_N)
#define EVALEQ_BIN_OFF (EVALEQ_UPSILON_OFF + EVALEQ_UPSILON_N)
#define EVALEQ_L2_OFF (EVALEQ_BIN_OFF + EVALEQ_BIN_N)
#define EVALEQ_INPUT_OFF (EVALEQ_L2_OFF + EVALEQ_L2_N)

/*
 * Maximum numbers of non-zero polys in the eq's quadratic term.
 */
#define QUADEQ_BETA3_MAXQ (3)
#define QUADEQ_BETA4_MAXQ (3)
#define EVALEQ_Z3_MAXQ (2 * ((m1) + (Z) + (l)))
#define EVALEQ_Z4_MAXQ (2 * ((m1) + (Z) + (l)))
#define EVALEQ_UPSILON_MAXQ (1)

/* Number of elements in an n x n (upper) diagonal matrix. */
#define NELEMS_DIAG(n) (((n) * (n) - (n)) / 2 + (n))

#endif
