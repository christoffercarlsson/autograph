#include "autograph/generate_key_pair.h"

#include "sodium.h"

bool generate_ephemeral_key_pair(unsigned char *private_key,
                                 unsigned char *public_key) {
  int result = crypto_box_keypair(public_key, private_key);
  return result == 0;
}

bool generate_identity_key_pair(unsigned char *private_key,
                                unsigned char *public_key) {
  int result = crypto_sign_keypair(public_key, private_key);
  return result == 0;
}
