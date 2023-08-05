#ifndef AUTOGRAPH_RANDOMBYTES_INTERNAL_H
#define AUTOGRAPH_RANDOMBYTES_INTERNAL_H

#include "sodium.h"

extern const struct randombytes_implementation
    autograph_randombytes_implementation;

#undef RANDOMBYTES_DEFAULT_IMPLEMENTATION
#define RANDOMBYTES_DEFAULT_IMPLEMENTATION &autograph_randombytes_implementation

#endif
