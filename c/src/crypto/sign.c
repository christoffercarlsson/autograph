#include "crypto.h"
#include "sodium.h"

int sign(unsigned char *signature, const unsigned char *private_key,
         const unsigned char *message, const unsigned long long message_size) {
  unsigned char sk[64];
  unsigned char pk[32];
  int seed_result = crypto_sign_seed_keypair(pk, sk, private_key);
  if (seed_result != 0) {
    return -1;
  }
  return crypto_sign_detached(signature, NULL, message, message_size, sk) == 0
             ? 0
             : -1;
}

int verify(const unsigned char *public_key, const unsigned char *message,
           const unsigned long long message_size,
           const unsigned char *signature) {
  return crypto_sign_verify_detached(signature, message, message_size,
                                     public_key) == 0
             ? 0
             : -1;
}
