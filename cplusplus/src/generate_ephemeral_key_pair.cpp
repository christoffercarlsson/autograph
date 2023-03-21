#include "autograph/generate_ephemeral_key_pair.h"

#include "autograph/create_key_pair.h"
#include "autograph/types.h"
#include "sodium.h"

KeyPair generate_ephemeral_key_pair() {
  auto key_pair = create_key_pair();
  int result = crypto_box_keypair(key_pair.public_key.data(),
                                  key_pair.private_key.data());
  if (result != 0) {
    throw std::runtime_error("Failed to generate X25519 key pair");
  }
  return std::move(key_pair);
}
