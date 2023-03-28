#include "autograph/autograph_init.h"

#include "sodium.h"

bool autograph_init() { return sodium_init() == 0; }
