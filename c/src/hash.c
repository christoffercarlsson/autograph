#include "crypto.h"
#include "sodium.h"

int hash(unsigned char *digest, const unsigned char *message,
         const unsigned long long message_size, const unsigned int iterations) {
  int initial_result = crypto_hash_sha512(digest, message, message_size);
  if (initial_result != 0) {
    return -1;
  }
  for (int i = 1; i < iterations; i++) {
    int result = crypto_hash_sha512(digest, digest, 64);
    if (result != 0) {
      return -1;
    }
  }
  return 0;
}
