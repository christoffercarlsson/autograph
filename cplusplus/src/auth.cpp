#include <string.h>

#include <cstdint>
#include <cstring>

#include "autograph.h"
#include "primitives.h"

constexpr uint16_t FINGERPRINT_ITERATIONS = 5200;
constexpr uint32_t FINGERPRINT_DIVISOR = 100000;
constexpr uint8_t FINGERPRINT_SIZE = 32;
constexpr uint8_t SAFETY_NUMBER_SIZE = FINGERPRINT_SIZE * 2;

extern "C" {

extern uint32_t get_uint32(const uint8_t *bytes, const size_t offset);

extern void set_uint32(uint8_t *bytes, const size_t offset,
                       const uint32_t number);

void encode_fingerprint(uint8_t *fingerprint, const uint8_t *digest) {
  for (uint8_t i = 0; i < FINGERPRINT_SIZE; i += 4) {
    uint32_t n = get_uint32(digest, i);
    set_uint32(fingerprint, i, n % FINGERPRINT_DIVISOR);
  }
}

bool calculate_fingerprint(uint8_t *fingerprint, const uint8_t *public_key,
                           const uint8_t *id, const size_t id_size) {
  size_t digest_size = autograph_primitive_digest_size();
  if (digest_size < FINGERPRINT_SIZE) {
    return false;
  }
  size_t public_key_size = autograph_identity_public_key_size();
  uint8_t input[public_key_size + id_size];
  memmove(input, public_key, public_key_size);
  memmove(input + public_key_size, id, id_size);
  uint8_t a[digest_size];
  uint8_t b[digest_size];
  if (!autograph_primitive_hash(a, input, sizeof input)) {
    return false;
  }
  for (uint16_t i = 1; i < FINGERPRINT_ITERATIONS; i++) {
    if (!autograph_primitive_hash(b, a, digest_size)) {
      return false;
    }
    memmove(a, b, digest_size);
  }
  encode_fingerprint(fingerprint, a);
  return true;
}

void calculate_safety_number(uint8_t *safety_number, uint8_t *our_fingerprint,
                             uint8_t *their_fingerprint) {
  if (memcmp(their_fingerprint, our_fingerprint, FINGERPRINT_SIZE) > 0) {
    memmove(safety_number, their_fingerprint, FINGERPRINT_SIZE);
    memmove(safety_number + FINGERPRINT_SIZE, our_fingerprint,
            FINGERPRINT_SIZE);
  } else {
    memmove(safety_number, our_fingerprint, FINGERPRINT_SIZE);
    memmove(safety_number + FINGERPRINT_SIZE, their_fingerprint,
            FINGERPRINT_SIZE);
  }
}

bool autograph_authenticate(uint8_t *safety_number,
                            const uint8_t *our_identity_key_pair,
                            const uint8_t *our_id, const size_t our_id_size,
                            const uint8_t *their_identity_key,
                            const uint8_t *their_id,
                            const size_t their_id_size) {
  uint8_t our_fingerprint[FINGERPRINT_SIZE];
  uint8_t their_fingerprint[FINGERPRINT_SIZE];
  uint8_t our_identity_key[autograph_identity_public_key_size()];
  autograph_get_identity_public_key(our_identity_key, our_identity_key_pair);
  if (!calculate_fingerprint(our_fingerprint, our_identity_key, our_id,
                             our_id_size)) {
    return false;
  }
  if (!calculate_fingerprint(their_fingerprint, their_identity_key, their_id,
                             their_id_size)) {
    return false;
  }
  calculate_safety_number(safety_number, our_fingerprint, their_fingerprint);
  return true;
}

size_t autograph_safety_number_size() { return SAFETY_NUMBER_SIZE; }

}  // extern "C"

namespace Autograph {

std::tuple<bool, Bytes> authenticate(const Bytes &ourIdentityKeyPair,
                                     const Bytes &ourId,
                                     const Bytes &theirIdentityKey,
                                     const Bytes &theirId) {
  Bytes safetyNumber(autograph_safety_number_size());
  bool success = autograph_authenticate(
      safetyNumber.data(), ourIdentityKeyPair.data(), ourId.data(),
      ourId.size(), theirIdentityKey.data(), theirId.data(), theirId.size());
  return {success, safetyNumber};
}

}  // namespace Autograph
