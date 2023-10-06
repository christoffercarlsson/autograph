#include <string.h>

#include "private.h"
#include "sodium.h"

int autograph_crypto_kdf_extract(unsigned char *prk, const unsigned char *salt,
                                 const unsigned char *ikm) {
  crypto_auth_hmacsha512_state state;
  crypto_auth_hmacsha512_init(&state, salt, 64);
  crypto_auth_hmacsha512_update(&state, ikm, 32);
  return crypto_auth_hmacsha512_final(&state, prk);
}

int autograph_crypto_kdf_expand(unsigned char *okm, const unsigned char *prk,
                                const unsigned char *context) {
  crypto_auth_hmacsha512_state state;
  crypto_auth_hmacsha512_init(&state, prk, 64);
  crypto_auth_hmacsha512_update(&state, context, 8);
  const unsigned char counter = 1;
  crypto_auth_hmacsha512_update(&state, &counter, 1);
  return crypto_auth_hmacsha512_final(&state, okm);
}

int autograph_crypto_kdf(unsigned char *secret_key, const unsigned char *ikm,
                         const unsigned char *context) {
  unsigned char salt[64];
  unsigned char prk[64];
  unsigned char okm[64];
  sodium_memzero(salt, 64);
  int extract_result = autograph_crypto_kdf_extract(prk, salt, ikm);
  if (extract_result != 0) {
    return -1;
  }
  int expand_result = autograph_crypto_kdf_expand(okm, prk, context);
  if (expand_result != 0) {
    return -1;
  }
  memmove(secret_key, okm, 32);
  return 0;
}
