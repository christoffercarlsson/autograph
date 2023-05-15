#include "autograph.h"
#include "sodium.h"

int autograph_init() { return sodium_init() >= 0 ? 0 : -1; }
