#include <string.h>

#include "autograph.h"
#include "constants.h"
#include "external.h"

size_t calculate_subject_size(const size_t data_size) {
  size_t max_size = UINT32_MAX - PUBLIC_KEY_SIZE;
  size_t size = data_size > max_size ? max_size : data_size;
  return size + PUBLIC_KEY_SIZE;
}

void calculate_subject(uint8_t *subject, const size_t subject_size,
                       const uint8_t *public_key, const uint8_t *data) {
  size_t key_offset = subject_size - PUBLIC_KEY_SIZE;
  memmove(subject, data, key_offset);
  memmove(subject + key_offset, public_key, PUBLIC_KEY_SIZE);
}

bool autograph_certify(uint8_t *signature, const uint8_t *our_identity_key_pair,
                       const uint8_t *their_identity_key, const uint8_t *data,
                       const size_t data_size) {
  if (data == NULL || data_size == 0) {
    return sign(signature, our_identity_key_pair, their_identity_key,
                PUBLIC_KEY_SIZE);
  }
  size_t subject_size = calculate_subject_size(data_size);
  uint8_t subject[subject_size];
  calculate_subject(subject, subject_size, their_identity_key, data);
  return sign(signature, our_identity_key_pair, subject, subject_size);
}

bool autograph_verify(const uint8_t *owner_identity_key,
                      const uint8_t *certifier_identity_key,
                      const uint8_t *signature, const uint8_t *data,
                      const size_t data_size) {
  if (data == NULL || data_size == 0) {
    return verify(certifier_identity_key, signature, owner_identity_key,
                  PUBLIC_KEY_SIZE);
  }
  size_t subject_size = calculate_subject_size(data_size);
  uint8_t subject[subject_size];
  calculate_subject(subject, subject_size, owner_identity_key, data);
  return verify(certifier_identity_key, signature, subject, subject_size);
}
