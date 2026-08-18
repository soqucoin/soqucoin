#ifndef STOPWATCH_H
#define STOPWATCH_H
#include "lazer.h"
#include <stdio.h>
#include <time.h>

#define STOPWATCH_SEC (1ULL)           /* seconds per second */
#define STOPWATCH_MSEC (1000ULL)       /* milliseconds per second */
#define STOPWATCH_USEC (1000000ULL)    /* microsecond per second */
#define STOPWATCH_NSEC (1000000000ULL) /* nanosecond per second */

typedef struct
{
  const char *name;
  struct timespec start;
  struct timespec stop;
  unsigned long long nsec;
  int stopped;
} stopwatch_struct;
typedef stopwatch_struct stopwatch_t[1];
typedef stopwatch_struct *stopwatch_ptr;
typedef const stopwatch_struct *stopwatch_srcptr;

#if TIMERS == TIMERS_ENABLED
#define STOPWATCH_T(__name__) stopwatch_t __name__

static inline unsigned long long
_stopwatch_diff (const struct timespec *start, const struct timespec *stop)
{
  return ((unsigned long long)stop->tv_sec - start->tv_sec) * STOPWATCH_NSEC
         + ((unsigned long long)stop->tv_nsec - start->tv_nsec);
}

static inline void
STOPWATCH_START (stopwatch_t timer, const char *name)
{
  timer->name = name;
  timer->stopped = 0;
  timer->nsec = 0;

  clock_gettime (CLOCK_MONOTONIC_RAW, &timer->start);
}

static inline void
STOPWATCH_STOP (stopwatch_t timer)
{
  clock_gettime (CLOCK_MONOTONIC_RAW, &timer->stop);

  timer->nsec = _stopwatch_diff (&timer->start, &timer->stop);
  timer->stopped = 1;
}

static inline void
STOPWATCH_PRINT (stopwatch_t timer, unsigned long long unit,
                 unsigned int indent)
{
  unsigned int i;

  ASSERT_ERR (timer->stopped == 1);
  ASSERT_ERR (unit == STOPWATCH_NSEC || unit == STOPWATCH_USEC
              || unit == STOPWATCH_MSEC || unit == STOPWATCH_SEC);

  for (i = 0; i < indent; i++)
    printf (" ");

  if (unit == STOPWATCH_NSEC)
    {
      printf ("timer %s: %llu nsec\n", timer->name, timer->nsec);
    }
  else if (unit == STOPWATCH_USEC)
    {
      printf ("timer %s: %.2Lf usec\n", timer->name,
              (long double)timer->nsec / (STOPWATCH_NSEC / STOPWATCH_USEC));
    }
  else if (unit == STOPWATCH_MSEC)
    {
      printf ("timer %s: %.2Lf msec\n", timer->name,
              (long double)timer->nsec / (STOPWATCH_NSEC / STOPWATCH_MSEC));
    }
  else if (unit == STOPWATCH_SEC)
    {
      printf ("timer %s: %.2Lf sec\n", timer->name,
              (long double)timer->nsec / (STOPWATCH_NSEC / STOPWATCH_SEC));
    }
  fflush (stdout);
}

#else
#define STOPWATCH_T(__name__) stopwatch_t __name__
#define STOPWATCH_START(__timer__, __name__) (void)0
#define STOPWATCH_STOP(__timer__) (void)0
#define STOPWATCH_PRINT(__timer__, __unit__, __indent__) (void)0
#endif

/* stopwatches */

extern STOPWATCH_T (stopwatch_blindsig_user_maskmsg);
extern STOPWATCH_T (stopwatch_blindsig_signer_sign);
extern STOPWATCH_T (stopwatch_blindsig_user_sign);
extern STOPWATCH_T (stopwatch_blindsig_verifier_vrfy);

extern STOPWATCH_T (stopwatch_lnp_prover_prove);
extern STOPWATCH_T (stopwatch_lnp_verifier_verify);

extern STOPWATCH_T (stopwatch_lnp_tbox_prove);
extern STOPWATCH_T (stopwatch_lnp_tbox_prove_tg);
extern STOPWATCH_T (stopwatch_lnp_tbox_prove_z34);
extern STOPWATCH_T (stopwatch_lnp_tbox_prove_auto);
extern STOPWATCH_T (stopwatch_lnp_tbox_prove_sz_beta3);
extern STOPWATCH_T (stopwatch_lnp_tbox_prove_sz_beta4);
extern STOPWATCH_T (stopwatch_lnp_tbox_prove_sz_upsilon);
extern STOPWATCH_T (stopwatch_lnp_tbox_prove_sz_bin);
extern STOPWATCH_T (stopwatch_lnp_tbox_prove_sz_l2);
extern STOPWATCH_T (stopwatch_lnp_tbox_prove_sz_z4);
extern STOPWATCH_T (stopwatch_lnp_tbox_prove_sz_z3);
extern STOPWATCH_T (stopwatch_lnp_tbox_prove_sz_auto);
extern STOPWATCH_T (stopwatch_lnp_tbox_prove_hi);

extern STOPWATCH_T (stopwatch_lnp_tbox_verify);
extern STOPWATCH_T (stopwatch_lnp_tbox_verify_sz_beta3);
extern STOPWATCH_T (stopwatch_lnp_tbox_verify_sz_beta4);
extern STOPWATCH_T (stopwatch_lnp_tbox_verify_sz_upsilon);
extern STOPWATCH_T (stopwatch_lnp_tbox_verify_sz_bin);
extern STOPWATCH_T (stopwatch_lnp_tbox_verify_sz_l2);
extern STOPWATCH_T (stopwatch_lnp_tbox_verify_sz_z4);
extern STOPWATCH_T (stopwatch_lnp_tbox_verify_sz_z3);
extern STOPWATCH_T (stopwatch_lnp_tbox_verify_sz_auto);

extern STOPWATCH_T (stopwatch_lnp_quad_many_prove);
extern STOPWATCH_T (stopwatch_lnp_quad_many_verify);

extern STOPWATCH_T (stopwatch_lnp_quad_prove);
extern STOPWATCH_T (stopwatch_lnp_quad_verify);

/* quad_eval not used anymore from tbox */
extern STOPWATCH_T (stopwatch_lnp_quad_eval_prove);
extern STOPWATCH_T (stopwatch_lnp_quad_eval_prove_compute_h);
extern STOPWATCH_T (stopwatch_lnp_quad_eval_verify);
extern STOPWATCH_T (stopwatch_lnp_quad_eval_schwartz_zippel_quad);
extern STOPWATCH_T (stopwatch_lnp_quad_eval_schwartz_zippel_lin);
extern STOPWATCH_T (stopwatch_lnp_quad_eval_schwartz_zippel_const);

#endif
