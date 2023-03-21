#include "autograph/sign_message.h"

#include "sodium.h"

Chunk sign_message(const Chunk &private_key, const Chunk &message) {
  Chunk signature(crypto_sign_BYTES);
  int result = crypto_sign_detached(signature.data(), nullptr, message.data(),
                                    message.size(), private_key.data());
  if (result != 0) {
    throw std::runtime_error("Failed to sign message");
  }
  return std::move(signature);
}
