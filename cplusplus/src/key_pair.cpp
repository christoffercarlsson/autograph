#include "autograph/key_pair.h"

#include <vector>

#include "autograph/core/key_pair.h"

namespace autograph {

KeyPair create_key_pair() {
  KeyPair key_pair;
  key_pair.public_key = Chunk(autograph_core_key_pair_PUBLIC_KEY_SIZE);
  key_pair.private_key = Chunk(autograph_core_key_pair_PRIVATE_KEY_SIZE);
  return std::move(key_pair);
}

KeyPair generate_ephemeral_key_pair() {
  auto key_pair = create_key_pair();
  int result = autograph_core_key_pair_ephemeral(key_pair.public_key.data(),
                                                 key_pair.private_key.data());
  if (result != 0) {
    throw std::runtime_error("Failed to generate ephemeral key pair");
  }
  return std::move(key_pair);
}

KeyPair generate_identity_key_pair() {
  auto key_pair = create_key_pair();
  int result = autograph_core_key_pair_identity(key_pair.public_key.data(),
                                                key_pair.private_key.data());
  if (result != 0) {
    throw std::runtime_error("Failed to generate identity key pair");
  }
  return std::move(key_pair);
}

}  // namespace autograph
