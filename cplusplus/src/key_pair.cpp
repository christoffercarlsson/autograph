#include <string.h>

#include "autograph.h"
#include "primitives.h"

extern "C" {

size_t autograph_identity_public_key_size() {
  return autograph_primitive_identity_public_key_size();
}

size_t autograph_session_public_key_size() {
  return autograph_primitive_session_public_key_size();
}

size_t autograph_identity_key_pair_size() {
  return autograph_primitive_identity_private_key_size() +
         autograph_primitive_identity_public_key_size();
}

size_t autograph_session_key_pair_size() {
  return autograph_primitive_session_private_key_size() +
         autograph_primitive_session_public_key_size();
}

bool autograph_identity_key_pair(uint8_t *key_pair) {
  return autograph_primitive_key_pair_identity(key_pair);
}

bool autograph_session_key_pair(uint8_t *key_pair) {
  return autograph_primitive_key_pair_session(key_pair);
}

void autograph_get_identity_public_key(uint8_t *public_key,
                                       const uint8_t *key_pair) {
  memmove(public_key,
          key_pair + autograph_primitive_identity_private_key_size(),
          autograph_primitive_identity_public_key_size());
}

void autograph_get_session_public_key(uint8_t *public_key,
                                      const uint8_t *key_pair) {
  memmove(public_key, key_pair + autograph_primitive_session_private_key_size(),
          autograph_primitive_session_public_key_size());
}

}  // extern "C"

namespace Autograph {

std::tuple<bool, Bytes> generateIdentityKeyPair() {
  Bytes keyPair(autograph_identity_key_pair_size());
  bool success = autograph_identity_key_pair(keyPair.data());
  return {success, keyPair};
}

std::tuple<bool, Bytes> generateSessionKeyPair() {
  Bytes keyPair(autograph_session_key_pair_size());
  bool success = autograph_session_key_pair(keyPair.data());
  return {success, keyPair};
}

Bytes getIdentityPublicKey(const Bytes &keyPair) {
  Bytes publicKey(autograph_identity_public_key_size());
  autograph_get_identity_public_key(publicKey.data(), keyPair.data());
  return publicKey;
}

Bytes getSessionPublicKey(const Bytes &keyPair) {
  Bytes publicKey(autograph_session_public_key_size());
  autograph_get_session_public_key(publicKey.data(), keyPair.data());
  return publicKey;
}

std::tuple<Bytes, Bytes> getPublicKeys(const Bytes &identityKeyPair,
                                       const Bytes &sessionKeyPair) {
  auto identityKey = getIdentityPublicKey(identityKeyPair);
  auto sessionKey = getSessionPublicKey(sessionKeyPair);
  return {identityKey, sessionKey};
}

}  // namespace Autograph
