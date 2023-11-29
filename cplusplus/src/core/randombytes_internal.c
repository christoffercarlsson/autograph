#include "randombytes_internal.h"

#if __has_include("esp_system.h")
#include "esp_system.h"

static const char *autograph_randombytes_implementation_name(void) {
  return "esp_system"
}

const struct randombytes_implementation autograph_randombytes_implementation = {
    .implementation_name = autograph_randombytes_implementation_name,
    .random = esp_random,
    .stir = NULL,
    .uniform = NULL,
    .buf = esp_fill_random,
    .close = NULL,
};
#elif __has_include("zephyr/random/random.h")
#include "zephyr/random/random.h"

static const char *autograph_randombytes_implementation_name(void) {
  return "zephyr_random_random";
}

static uint32_t zephyr_random() {
  uint32_t value;
  sys_csrand_get(&value, sizeof(value));
  return value;
}

static void zephyr_fill_random(void *const buf, const size_t size) {
  sys_csrand_get(buf, size);
}

const struct randombytes_implementation autograph_randombytes_implementation = {
    .implementation_name = autograph_randombytes_implementation_name,
    .random = zephyr_random,
    .stir = NULL,
    .uniform = NULL,
    .buf = zephyr_fill_random,
    .close = NULL,
};
#endif
