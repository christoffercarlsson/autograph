#include "autograph/verify_signature.h"

#include "sodium.h"

bool verify_signature(const unsigned char *public_key,
                      const unsigned char *message,
                      const unsigned long long message_size,
                      const unsigned char *signature) {
  int result =
      crypto_sign_verify_detached(signature, message, message_size, public_key);
  return result == 0;
}
