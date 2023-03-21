#include "autograph/verify_signature.h"

#include "sodium.h"

bool verify_signature(const Chunk &public_key, const Chunk &message,
                      const Chunk &signature) {
  int result = crypto_sign_verify_detached(signature.data(), message.data(),
                                           message.size(), public_key.data());
  return result == 0;
}
