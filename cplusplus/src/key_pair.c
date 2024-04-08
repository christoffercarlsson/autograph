#include <string.h>

#include "autograph.h"
#include "constants.h"
#include "external.h"

bool autograph_identity_key_pair(uint8_t *key_pair) {
  if (!ready()) {
    return false;
  }
  return key_pair_identity(key_pair);
}

bool autograph_session_key_pair(uint8_t *key_pair) {
  if (!ready()) {
    return false;
  }
  return key_pair_session(key_pair);
}

void autograph_get_public_key(uint8_t *public_key, const uint8_t *key_pair) {
  memmove(public_key, key_pair + PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE);
}
