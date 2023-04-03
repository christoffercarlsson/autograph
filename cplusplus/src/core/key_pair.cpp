#include "autograph.h"
#include "sodium.h"

int autograph_key_pair_ephemeral(unsigned char *private_key,
                                 unsigned char *public_key) {
  return crypto_box_keypair(public_key, private_key) == 0 ? 0 : -1;
}

int autograph_key_pair_identity(unsigned char *private_key,
                                unsigned char *public_key) {
  return crypto_sign_keypair(public_key, private_key) == 0 ? 0 : -1;
}
