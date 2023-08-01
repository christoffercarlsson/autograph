#include "randombytes_internal.h"

#ifdef CONFIG_IDF_TARGET
#include "esp_system.h"

static const char *autograph_randombytes_implementation_name(void) {
  return CONFIG_IDF_TARGET;
}

const struct randombytes_implementation autograph_randombytes_implementation = {
    .implementation_name = autograph_randombytes_implementation_name,
    .random = esp_random,
    .stir = NULL,
    .uniform = NULL,
    .buf = esp_fill_random,
    .close = NULL,
};
#endif
