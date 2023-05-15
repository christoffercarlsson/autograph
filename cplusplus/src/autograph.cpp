#include "autograph.hpp"

#include <stdexcept>
#include <string>

#include "autograph.h"
#include "private.hpp"

namespace autograph {

Party create_initiator(const KeyPair &identity_key_pair,
                       KeyPair &ephemeral_key_pair) {
  auto party = create_party(true, identity_key_pair, ephemeral_key_pair);
  return std::move(party);
}

Party create_responder(const KeyPair &identity_key_pair,
                       KeyPair &ephemeral_key_pair) {
  auto party = create_party(false, identity_key_pair, ephemeral_key_pair);
  return std::move(party);
}

KeyPair create_key_pair() {
  Bytes private_key(PRIVATE_KEY_SIZE);
  Bytes public_key(PUBLIC_KEY_SIZE);
  KeyPair key_pair = {private_key, public_key};
  return std::move(key_pair);
}

KeyPair generate_ephemeral_key_pair() {
  auto key_pair = create_key_pair();
  bool success = autograph_key_pair_ephemeral(key_pair.private_key.data(),
                                              key_pair.public_key.data()) == 0;
  if (!success) {
    throw std::runtime_error("Ephemeral key pair generation failed");
  }
  return std::move(key_pair);
}

KeyPair generate_identity_key_pair() {
  auto key_pair = create_key_pair();
  bool success = autograph_key_pair_identity(key_pair.private_key.data(),
                                             key_pair.public_key.data()) == 0;
  if (!success) {
    throw std::runtime_error("Identity key pair generation failed");
  }
  return std::move(key_pair);
}

void init() {
  bool success = autograph_init() == 0;
  if (!success) {
    throw std::runtime_error("Initialization failed");
  }
}

}  // namespace autograph
