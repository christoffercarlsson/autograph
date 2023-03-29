#include "autograph/crypto/kdf.h"

#include "sodium.h"

bool autograph_crypto_kdf(unsigned char *secret_key, const unsigned char *ikm,
                          const unsigned char context) {
  unsigned char salt[crypto_auth_hmacsha512_BYTES];
  sodium_memzero(salt, crypto_auth_hmacsha512_BYTES);
  unsigned char prk[crypto_auth_hmacsha512_BYTES];
  int extract_result =
      crypto_auth_hmacsha512(prk, ikm, crypto_scalarmult_BYTES, salt);
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
