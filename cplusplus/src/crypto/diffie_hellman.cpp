#include "autograph/crypto/diffie_hellman.h"

#include "sodium.h"

bool autograph_crypto_diffie_hellman(unsigned char *shared_secret,
                                     const unsigned char *our_private_key,
                                     const unsigned char *their_public_key) {
  int result =
      crypto_scalarmult(shared_secret, our_private_key, their_public_key);
  return result == 0;
}
