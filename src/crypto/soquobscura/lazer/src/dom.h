#ifndef DOM_H
#define DOM_H
#include <stdint.h>

union dom
{
  uint32_t d32[2];
  uint64_t d64;
};

#endif
