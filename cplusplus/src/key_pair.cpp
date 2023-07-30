#include "key_pair.h"

namespace autograph {

KeyPair create_key_pair() {
  Bytes private_key(32);
  Bytes public_key(32);
  KeyPair key_pair = {private_key, public_key};
  return key_pair;
}

KeyPairResult generate_ephemeral_key_pair() {
  auto key_pair = create_key_pair();
  bool success = autograph_key_pair_ephemeral(key_pair.private_key.data(),
                                              key_pair.public_key.data()) == 0;
  KeyPairResult result = {success, key_pair};
  return result;
}

KeyPairResult generate_identity_key_pair() {
  auto key_pair = create_key_pair();
  bool success = autograph_key_pair_identity(key_pair.private_key.data(),
                                             key_pair.public_key.data()) == 0;
  KeyPairResult result = {success, key_pair};
  return result;
}

}  // namespace autograph
