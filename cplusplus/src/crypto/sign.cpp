#include "crypto.hpp"
#include "sodium.h"

namespace autograph {

bool sign(unsigned char *signature, const unsigned char *private_key,
          const unsigned char *message, const unsigned long long message_size) {
  return crypto_sign_detached(signature, nullptr, message, message_size,
                              private_key) == 0;
}

bool verify(const unsigned char *public_key, const unsigned char *message,
            const unsigned long long message_size,
            const unsigned char *signature) {
  return crypto_sign_verify_detached(signature, message, message_size,
                                     public_key) == 0;
}

}  // namespace autograph
