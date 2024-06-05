#include <string.h>

#include "autograph.h"
#include "constants.h"
#include "external.h"

extern "C" {

bool autograph_identity_key_pair(uint8_t *key_pair) {
  return key_pair_identity(key_pair);
}

bool autograph_session_key_pair(uint8_t *key_pair) {
  return key_pair_session(key_pair);
}

void autograph_get_public_key(uint8_t *public_key, const uint8_t *key_pair) {
  memmove(public_key, key_pair + PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE);
}

}  // extern "C"

namespace Autograph {

std::tuple<bool, KeyPair> generateIdentityKeyPair() {
  KeyPair keyPair;
  bool success = autograph_identity_key_pair(keyPair.data());
  return {success, keyPair};
}

std::tuple<bool, KeyPair> generateSessionKeyPair() {
  KeyPair keyPair;
  bool success = autograph_session_key_pair(keyPair.data());
  return {success, keyPair};
}

PublicKey getPublicKey(const KeyPair &keyPair) {
  PublicKey publicKey;
  autograph_get_public_key(publicKey.data(), keyPair.data());
  return publicKey;
}

std::tuple<PublicKey, PublicKey> getPublicKeys(const KeyPair &identityKeyPair,
                                               const KeyPair &sessionKeyPair) {
  auto identityKey = getPublicKey(identityKeyPair);
  auto sessionKey = getPublicKey(sessionKeyPair);
  return {identityKey, sessionKey};
}

}  // namespace Autograph
