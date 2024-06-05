#ifndef AUTOGRAPH_HELPERS_H
#define AUTOGRAPH_HELPERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t get_uint32(const uint8_t *bytes, const size_t offset);

void set_uint32(uint8_t *bytes, const size_t offset, const uint32_t number);

void zeroize(uint8_t *data, const size_t data_size);

#ifdef __cplusplus
}
#endif

#endif
