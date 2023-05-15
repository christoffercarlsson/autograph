#include "constants.hpp"
#include "crypto.hpp"
#include "sodium.h"
#include "types.hpp"

namespace autograph {

bool kdf(unsigned char *secret_key, const unsigned char *ikm,
         const unsigned char context) {
  Bytes salt(DIGEST_SIZE);
  Bytes prk(DIGEST_SIZE);
  int extract_result =
      crypto_auth_hmacsha512(prk.data(), ikm, DH_OUTPUT_SIZE, salt.data());
  if (extract_result != 0) {
    return false;
  }
  const Bytes data = {context, 1};
  int expand_result =
      crypto_auth_hmacsha512(secret_key, data.data(), 2, prk.data());
  if (expand_result != 0) {
    return false;
  }
  return true;
}

}  // namespace autograph
