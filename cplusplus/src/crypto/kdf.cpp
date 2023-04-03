#include "constants.hpp"
#include "crypto.hpp"
#include "sodium.h"

namespace autograph {

bool kdf(unsigned char *secret_key, const unsigned char *ikm,
         const unsigned char context) {
  unsigned char salt[DIGEST_SIZE];
  sodium_memzero(salt, DIGEST_SIZE);
  unsigned char prk[DIGEST_SIZE];
  int extract_result = crypto_auth_hmacsha512(prk, ikm, DH_OUTPUT_SIZE, salt);
  if (extract_result != 0) {
    return false;
  }
  const unsigned char data[] = {context, 0x01};
  int expand_result = crypto_auth_hmacsha512(secret_key, data, 2, prk);
  if (expand_result != 0) {
    return false;
  }
  return true;
}

}  // namespace autograph
