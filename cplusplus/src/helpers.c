#include "constants.h"
#include "external.h"

void autograph_zeroize(uint8_t *data, const size_t data_size) {
  zeroize(data, data_size);
}

bool autograph_is_zero(const uint8_t *data, const size_t data_size) {
  return is_zero(data, data_size);
}

size_t autograph_key_pair_size() { return KEY_PAIR_SIZE; }

size_t autograph_nonce_size() { return NONCE_SIZE; }

size_t autograph_public_key_size() { return PUBLIC_KEY_SIZE; }

size_t autograph_safety_number_size() { return SAFETY_NUMBER_SIZE; }

size_t autograph_secret_key_size() { return SECRET_KEY_SIZE; }

size_t autograph_signature_size() { return SIGNATURE_SIZE; }

size_t autograph_transcript_size() { return TRANSCRIPT_SIZE; }
