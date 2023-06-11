#include "crypto.h"
#include "sodium.h"

int kdf(unsigned char *secret_key, const unsigned char *ikm,
        const unsigned char context) {
  unsigned char salt[64];
  sodium_memzero(salt, 64);
  unsigned char prk[64];
  int extract_result = crypto_auth_hmacsha512(prk, ikm, 32, salt);
  if (extract_result != 0) {
    return -1;
  }
  const unsigned char data[] = {context, 1};
  int expand_result = crypto_auth_hmacsha512(secret_key, data, 2, prk);
  if (expand_result != 0) {
    return -1;
  }
  return 0;
}
