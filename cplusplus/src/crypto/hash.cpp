#include "autograph/crypto/hash.h"

#include "sodium.h"

bool autograph_crypto_hash(unsigned char *digest, const unsigned char *message,
                           const unsigned long long message_size,
                           const unsigned int iterations) {
  int initial_result = crypto_hash_sha512(digest, message, message_size);
  if (initial_result != 0) {
    return false;
  }
  for (int i = 1; i < iterations; i++) {
    int result = crypto_hash_sha512(digest, digest, crypto_hash_sha512_BYTES);
    if (result != 0) {
      return false;
    }
  }
  return true;
}
