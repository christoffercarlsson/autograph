#include "crypto.hpp"
#include "sodium.h"

namespace autograph {

bool diffie_hellman(unsigned char *shared_secret,
                    const unsigned char *our_private_key,
                    const unsigned char *their_public_key) {
  return crypto_scalarmult(shared_secret, our_private_key, their_public_key) ==
         0;
}

}  // namespace autograph
