#include <stdexcept>
#include <string>

#include "internal.h"

namespace autograph {

Party create_initiator(const KeyPair identity_key_pair,
                       KeyPair ephemeral_key_pair) {
  return create_party(true, identity_key_pair, ephemeral_key_pair);
}

Party create_responder(const KeyPair identity_key_pair,
                       KeyPair ephemeral_key_pair) {
  return create_party(false, identity_key_pair, ephemeral_key_pair);
}

KeyPair create_key_pair() {
  Bytes private_key(32);
  Bytes public_key(32);
  KeyPair key_pair = {private_key, public_key};
  return key_pair;
}

KeyPair generate_ephemeral_key_pair() {
  auto key_pair = create_key_pair();
  int result = autograph_key_pair_ephemeral(key_pair.private_key.data(),
                                            key_pair.public_key.data());
  if (result != 0) {
    throw std::runtime_error("Ephemeral key pair generation failed");
  }
  return key_pair;
}

KeyPair generate_identity_key_pair() {
  auto key_pair = create_key_pair();
  int result = autograph_key_pair_identity(key_pair.private_key.data(),
                                           key_pair.public_key.data());
  if (result != 0) {
    throw std::runtime_error("Identity key pair generation failed");
  }
  return key_pair;
}

void init() {
  int result = autograph_init();
  if (result != 0) {
    throw std::runtime_error("Initialization failed");
  }
}

}  // namespace autograph
