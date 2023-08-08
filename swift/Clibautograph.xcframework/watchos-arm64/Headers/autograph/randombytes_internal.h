#ifndef AUTOGRAPH_RANDOMBYTES_INTERNAL_H
#define AUTOGRAPH_RANDOMBYTES_INTERNAL_H

#include "sodium.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const struct randombytes_implementation
    autograph_randombytes_implementation;

#undef RANDOMBYTES_DEFAULT_IMPLEMENTATION
#define RANDOMBYTES_DEFAULT_IMPLEMENTATION &autograph_randombytes_implementation

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
