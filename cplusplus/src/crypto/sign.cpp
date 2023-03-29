#include "autograph/crypto/sign.h"

#include "sodium.h"

bool autograph_crypto_sign(unsigned char *signature,
                           const unsigned char *private_key,
                           const unsigned char *message,
                           const unsigned long long message_size) {
  int result = crypto_sign_detached(signature, nullptr, message, message_size,
                                    private_key);
  return result == 0;
}

bool autograph_crypto_sign_verify(const unsigned char *public_key,
                                  const unsigned char *message,
                                  const unsigned long long message_size,
                                  const unsigned char *signature) {
  int result =
      crypto_sign_verify_detached(signature, message, message_size, public_key);
  return result == 0;
}
