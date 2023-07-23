#include "internal.h"

namespace autograph {

Party create_initiator(const SignFunction sign,
                       const Bytes identity_public_key) {
  return create_party(true, sign, identity_public_key);
}

Party create_initiator(const KeyPair identity_key_pair) {
  return create_initiator(create_sign(identity_key_pair.private_key),
                          identity_key_pair.public_key);
}

Party create_responder(const SignFunction sign,
                       const Bytes identity_public_key) {
  return create_party(false, sign, identity_public_key);
}

Party create_responder(const KeyPair identity_key_pair) {
  return create_responder(create_sign(identity_key_pair.private_key),
                          identity_key_pair.public_key);
}

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

bool init() { return autograph_init() == 0; }

}  // namespace autograph
