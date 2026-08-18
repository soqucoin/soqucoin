#include "abdlop.c"
#include "aes256ctr-amd64.c"
#include "aes256ctr.c"
/* REMOVED by option-4 extraction: zero reachable function bodies
 * on the verify path, proven by --gc-sections. was: #include "blindsig.c" */
#include "brandom.c"
/* REMOVED by option-4 extraction: zero reachable function bodies
 * on the verify path, proven by --gc-sections. was: #include "bytes.c" */
#include "coder.c"
#include "dcompress.c"
/* REMOVED by option-4 extraction: zero reachable function bodies
 * on the verify path, proven by --gc-sections. was: #include "dump.c" */
/* REMOVED by option-4 extraction: zero reachable function bodies
 * on the verify path, proven by --gc-sections. was: #include "grandom.c" */
#include "int.c"
#include "intmat.c"
#include "intvec.c"
#include "lin-proofs.c"
/* REMOVED by option-4 extraction: zero reachable function bodies
 * on the verify path, proven by --gc-sections. was: #include "lnp-quad-eval.c" */
#include "lnp-quad-many.c"
#include "lnp-quad.c"
/* REMOVED by option-4 extraction: zero reachable function bodies
 * on the verify path, proven by --gc-sections. was: #include "lnp-tbox.c" */
/* REMOVED by option-4 extraction: zero reachable function bodies
 * on the verify path, proven by --gc-sections. was: #include "lnp.c" */
#include "memory.c"
#include "poly.c"
#include "polymat.c"
/* REMOVED by option-4 extraction: zero reachable function bodies
 * on the verify path, proven by --gc-sections. was: #include "polyring.c" */
#include "polyvec.c"
#include "quad.c"
/* REMOVED by option-4 extraction: zero reachable function bodies
 * on the verify path, proven by --gc-sections. was: #include "rejection.c" */
#include "rng.c"
#include "shake128.c"
#include "spolymat.c"
#include "spolyvec.c"
/* REMOVED by option-4 extraction: zero reachable function bodies, and with
 * TIMERS == TIMERS_DISABLED the STOPWATCH_START/STOP macros are (void)0 so nothing
 * references the timer globals. was: #include "stopwatch.c" */
#include "urandom.c"
/* REMOVED by option-4 extraction: zero reachable function bodies
 * on the verify path, proven by --gc-sections. was: #include "version.c" */

__attribute__ ((destructor)) void lazer_fini (void);

void *hexl_ntt_d64[NMODULI_D64];
void *hexl_ntt_d128[NMODULI_D128];

void
lazer_init (void)
{
  static int lazer_init = 0;
  unsigned int i;

  if (lazer_init == 0)
    {
      lazer_init = 1;

      for (i = 0; i < NMODULI_D64; i++)
        {
          hexl_ntt_d64[i] = hexl_ntt_alloc (64, moduli_d64[i]->p);
        }
      for (i = 0; i < NMODULI_D128; i++)
        {
          hexl_ntt_d128[i] = hexl_ntt_alloc (128, moduli_d128[i]->p);
        }
    }
}

void
lazer_fini (void)
{
  unsigned int i;

  for (i = 0; i < NMODULI_D64; i++)
    {
      hexl_ntt_free (hexl_ntt_d64[i]);
    }
  for (i = 0; i < NMODULI_D128; i++)
    {
      hexl_ntt_free (hexl_ntt_d128[i]);
    }
}

unsigned long
lin_params_get_prooflen (const lin_params_t params)
{
  return params->tbox_params->prooflen;
}

#if DEBUGINFO == DEBUGINFO_ENABLED
struct debuginfo debug = {0};
#endif