#include "autograph/diffie_hellman.h"

#include "sodium.h"

Chunk diffie_hellman(const Chunk &private_key, const Chunk &public_key) {
  Chunk shared_key(crypto_scalarmult_BYTES);
  int result = crypto_scalarmult(shared_key.data(), private_key.data(),
                                 public_key.data());
  if (result != 0) {
    throw std::runtime_error("Failed to perform key exchange");
  }
  return std::move(shared_key);
}
