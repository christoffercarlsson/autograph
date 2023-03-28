#include <algorithm>

#include "autograph/constants.h"
#include "sodium.h"

constexpr unsigned char CONTEXT_INITIATOR = 0x00;
constexpr unsigned char CONTEXT_RESPONDER = 0x01;

bool kdf(unsigned char *secret_key, const unsigned char *ikm,
         const unsigned char info) {
  unsigned char salt[crypto_auth_hmacsha512_BYTES];
  sodium_memzero(salt, crypto_auth_hmacsha512_BYTES);
  unsigned char prk[crypto_auth_hmacsha512_BYTES];
  int extract_result =
      crypto_auth_hmacsha512(prk, ikm, crypto_scalarmult_BYTES, salt);
  if (extract_result != 0) {
    return false;
  }
  const unsigned char data[] = {info, 0x01};
  int expand_result = crypto_auth_hmacsha512(secret_key, data, 2, prk);
  if (expand_result != 0) {
    return false;
  }
  return true;
}

bool derive_secret_keys(unsigned char *our_secret_key,
                        unsigned char *their_secret_key, bool is_initiator,
                        unsigned char *our_private_key,
                        const unsigned char *their_public_key) {
  unsigned char ikm[crypto_scalarmult_BYTES];
  int dh_result = crypto_scalarmult(ikm, our_private_key, their_public_key);
  bool our_key_result =
      kdf(our_secret_key, ikm,
          is_initiator ? CONTEXT_INITIATOR : CONTEXT_RESPONDER);
  bool their_key_result =
      kdf(their_secret_key, ikm,
          is_initiator ? CONTEXT_RESPONDER : CONTEXT_INITIATOR);
  sodium_memzero(our_private_key, PRIVATE_KEY_SIZE);
  sodium_memzero(ikm, crypto_scalarmult_BYTES);
  return dh_result == 0 && our_key_result && their_key_result;
}
