#include "autograph.h"

namespace Autograph {

tuple<bool, KeyPair> generateIdentityKeyPair() {
  KeyPair keyPair;
  bool success = autograph_identity_key_pair(keyPair.data());
  return make_tuple(success, keyPair);
}

tuple<bool, KeyPair> generateSessionKeyPair() {
  KeyPair keyPair;
  bool success = autograph_session_key_pair(keyPair.data());
  return make_tuple(success, keyPair);
}

PublicKey getPublicKey(const KeyPair &keyPair) {
  PublicKey publicKey;
  autograph_get_public_key(publicKey.data(), keyPair.data());
  return publicKey;
}

}  // namespace Autograph
