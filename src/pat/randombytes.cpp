#include "random.h"
#include "support/cleanse.h"

extern "C" void randombytes(unsigned char *x, unsigned long long xlen)
{
    GetStrongRandBytes(x, xlen);
}

