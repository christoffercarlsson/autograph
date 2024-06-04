#include "helpers.h"

#include "autograph.h"
#include "constants.h"
#include "sodium.h"

uint32_t get_uint32(const uint8_t *bytes, const size_t offset) {
  uint32_t number = ((uint32_t)bytes[offset] << 24) |
                    ((uint32_t)bytes[offset + 1] << 16) |
                    ((uint32_t)bytes[offset + 2] << 8) | bytes[offset + 3];
  return number;
}

void set_uint32(uint8_t *bytes, const size_t offset, const uint32_t number) {
  bytes[offset] = (number >> 24) & 0xFF;
  bytes[offset + 1] = (number >> 16) & 0xFF;
  bytes[offset + 2] = (number >> 8) & 0xFF;
  bytes[offset + 3] = number & 0xFF;
}

void zeroize(uint8_t *data, const size_t data_size) {
  sodium_memzero(data, data_size);
}

uint16_t autograph_skipped_indexes_count() {
  return DEFAULT_SKIPPED_INDEXES_COUNT;
}

size_t autograph_key_pair_size() { return KEY_PAIR_SIZE; }

size_t autograph_nonce_size() { return NONCE_SIZE; }

size_t autograph_public_key_size() { return PUBLIC_KEY_SIZE; }

size_t autograph_safety_number_size() { return SAFETY_NUMBER_SIZE; }

size_t autograph_secret_key_size() { return SECRET_KEY_SIZE; }

size_t autograph_signature_size() { return SIGNATURE_SIZE; }

size_t autograph_transcript_size() { return TRANSCRIPT_SIZE; }
