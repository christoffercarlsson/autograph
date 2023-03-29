#include "autograph/core/key_pair.h"

#include "sodium.h"

int autograph_core_key_pair_ephemeral(unsigned char *private_key,
                                      unsigned char *public_key) {
  int result = crypto_box_keypair(public_key, private_key);
  return result == 0 ? 0 : -1;
}

int autograph_core_key_pair_identity(unsigned char *private_key,
                                     unsigned char *public_key) {
  int result = crypto_sign_keypair(public_key, private_key);
  return result == 0 ? 0 : -1;
}
