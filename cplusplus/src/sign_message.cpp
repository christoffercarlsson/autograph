#include "autograph/sign_message.h"

#include "sodium.h"

bool sign_message(unsigned char *signature, const unsigned char *private_key,
                  const unsigned char *message,
                  const unsigned long long message_size) {
  int result = crypto_sign_detached(signature, nullptr, message, message_size,
                                    private_key);
  return result == 0;
}
