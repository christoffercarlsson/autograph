#include "autograph.h"
#include "crypto.hpp"

namespace autograph {

unsigned int encrypt_index = 0;

}  // namespace autograph

int autograph_decrypt(unsigned char *plaintext, const unsigned char *key,
                      const unsigned char *message,
                      const unsigned long long message_size) {
  const unsigned int index =
      (message[0] << 24) | (message[1] << 16) | (message[2] << 8) | message[3];
  return autograph::decrypt(plaintext, key, index, message + 4,
                            message_size - 4)
             ? 0
             : -1;
}

int autograph_encrypt(unsigned char *message, const unsigned char *key,
                      const unsigned char *plaintext,
                      const unsigned long long plaintext_size) {
  autograph::encrypt_index++;
  bool result = autograph::encrypt(message + 4, key, autograph::encrypt_index,
                                   plaintext, plaintext_size);
  if (!result) {
    return -1;
  }
  message[0] = (autograph::encrypt_index >> 24) & 0xFF;
  message[1] = (autograph::encrypt_index >> 16) & 0xFF;
  message[2] = (autograph::encrypt_index >> 8) & 0xFF;
  message[3] = autograph::encrypt_index & 0xFF;
  return 0;
}
