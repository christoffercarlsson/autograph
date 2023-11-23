#include "key_pair.h"

#include "error.h"
#include "init.h"
#include "sizes.h"

namespace Autograph {

KeyPair createKeyPair() {
  std::vector<unsigned char> privateKey(PRIVATE_KEY_SIZE);
  std::vector<unsigned char> publicKey(PUBLIC_KEY_SIZE);
  KeyPair keyPair = {privateKey, publicKey};
  return keyPair;
}

KeyPair generateEphemeralKeyPair() {
  if (autograph_init() != 0) {
    throw Error(Error::Initialization);
  }
  auto keyPair = createKeyPair();
  bool success = autograph_key_pair_ephemeral(keyPair.privateKey.data(),
                                              keyPair.publicKey.data()) == 0;
  if (!success) {
    throw Error(Error::KeyPairGeneration);
  }
  return keyPair;
}

KeyPair generateIdentityKeyPair() {
  if (autograph_init() != 0) {
    throw Error(Error::Initialization);
  }
  auto keyPair = createKeyPair();
  bool success = autograph_key_pair_identity(keyPair.privateKey.data(),
                                             keyPair.publicKey.data()) == 0;
  if (!success) {
    throw Error(Error::KeyPairGeneration);
  }
  return keyPair;
}

}  // namespace Autograph
