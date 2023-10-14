#include <string.h>

#include "private.h"
#include "sodium.h"

int autograph_crypto_hash(unsigned char *digest, const unsigned char *message,
                          const unsigned int message_size,
                          const unsigned int iterations) {
  unsigned char d[64];
  int initial_result = crypto_hash_sha512(digest, message, message_size);
  if (initial_result != 0) {
    return -1;
  }
  for (int i = 1; i < iterations; i++) {
    int result = crypto_hash_sha512(d, digest, 64);
    if (result != 0) {
      return -1;
    }
    memmove(digest, d, 64);
  }
  return 0;
}
