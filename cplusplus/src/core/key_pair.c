#include "key_pair.h"

#include <string.h>

#include "sodium.h"

int autograph_key_pair_ephemeral(unsigned char *private_key,
                                 unsigned char *public_key) {
  return crypto_box_keypair(public_key, private_key) == 0 ? 0 : -1;
}

int autograph_key_pair_identity(unsigned char *private_key,
                                unsigned char *public_key) {
  unsigned char sk[64];
  int result;
  result = crypto_sign_keypair(public_key, sk) == 0 ? 0 : -1;
  memmove(private_key, sk, 32);
  sodium_memzero(sk, sizeof sk);
  return result;
}
