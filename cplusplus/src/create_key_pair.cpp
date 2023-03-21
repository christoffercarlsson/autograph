#include "autograph/create_key_pair.h"

#include "sodium.h"

KeyPair create_key_pair() {
  KeyPair key_pair;
  key_pair.public_key = Chunk(crypto_box_PUBLICKEYBYTES);
  key_pair.private_key = Chunk(crypto_box_SECRETKEYBYTES);
  return std::move(key_pair);
}
