#include "autograph/generate_ephemeral_key_pair.h"

KeyPair create_key_pair() {
  KeyPair key_pair;
  key_pair.public_key = Chunk(crypto_box_PUBLICKEYBYTES);
  key_pair.private_key = Chunk(crypto_box_SECRETKEYBYTES);
  return std::move(key_pair);
}

KeyPair generate_ephemeral_key_pair() {
  auto key_pair = create_key_pair();
  int result = crypto_box_keypair(key_pair.public_key.data(),
                                  key_pair.private_key.data());
  if (result != 0) {
    throw std::runtime_error("Failed to generate X25519 key pair");
  }
  return std::move(key_pair);
}
