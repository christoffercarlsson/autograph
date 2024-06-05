#include <string.h>

#include "autograph.h"
#include "constants.h"
#include "external.h"
#include "support.h"

extern "C" {

void encode_fingerprint(uint8_t *fingerprint, const uint8_t *digest) {
  for (uint8_t i = 0; i < FINGERPRINT_SIZE; i += 4) {
    uint32_t n = get_uint32(digest, i);
    set_uint32(fingerprint, i, n % FINGERPRINT_DIVISOR);
  }
}

bool calculate_fingerprint(uint8_t *fingerprint, const uint8_t *public_key) {
  uint8_t a[DIGEST_SIZE];
  uint8_t b[DIGEST_SIZE];
  if (!hash(a, public_key, PUBLIC_KEY_SIZE)) {
    return false;
  }
  for (uint16_t i = 1; i < FINGERPRINT_ITERATIONS; i++) {
    if (!hash(b, a, DIGEST_SIZE)) {
      return false;
    }
    memmove(a, b, DIGEST_SIZE);
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
                            const uint8_t *identity_key_pair,
                            const uint8_t *their_identity_key) {
  uint8_t our_fingerprint[FINGERPRINT_SIZE];
  uint8_t their_fingerprint[FINGERPRINT_SIZE];
  uint8_t our_identity_key[PUBLIC_KEY_SIZE];
  autograph_get_public_key(our_identity_key, identity_key_pair);
  if (!calculate_fingerprint(our_fingerprint, our_identity_key)) {
    return false;
  }
  if (!calculate_fingerprint(their_fingerprint, their_identity_key)) {
    return false;
  }
  calculate_safety_number(safety_number, our_fingerprint, their_fingerprint);
  return true;
}

}  // extern "C"

namespace Autograph {

std::tuple<bool, SafetyNumber> authenticate(const KeyPair &ourIdentityKeyPair,
                                            const PublicKey &theirIdentityKey) {
  SafetyNumber safetyNumber;
  bool success = autograph_authenticate(
      safetyNumber.data(), ourIdentityKeyPair.data(), theirIdentityKey.data());
  return {success, safetyNumber};
}

}  // namespace Autograph
