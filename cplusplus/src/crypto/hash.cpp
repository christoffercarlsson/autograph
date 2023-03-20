#include "autograph/crypto.h"

void hash_sha512(const Chunk &message, Chunk &digest) {
  int result =
      crypto_hash_sha512(digest.data(), message.data(), message.size());
  if (result != 0) {
    throw std::runtime_error("Failed to hash message");
  }
}

Chunk hash(const Chunk &message, unsigned int iterations) {
  Chunk digest(crypto_generichash_BYTES);
  hash_sha512(message, digest);
  for (int i = 1; i < iterations; i++) {
    hash_sha512(digest, digest);
  }
  return std::move(digest);
}
