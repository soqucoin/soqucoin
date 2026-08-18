#include "memory.h"
#include "lazer.h"

#include <stddef.h>
#include <stdlib.h>

/* option-4 prune (no-inline reachability): ld discarded .text.lazer_set_memory_functions */

/* option-4 prune (no-inline reachability): ld discarded .text.lazer_get_memory_functions */

static void *
alloc_default (size_t len)
{
  void *mem;

  //XXXASSERT_ERR (len > 0);

  mem = malloc (len);
  ERR (mem == NULL, "malloc failed (size %llu).", (unsigned long long)len);
  return mem;
}

/* option-4 prune (no-inline reachability): ld discarded .text.realloc_default */

static void
free_default (void *mem, UNUSED size_t len)
{
  free (mem);
}
