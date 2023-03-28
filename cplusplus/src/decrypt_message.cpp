#include "autograph/decrypt_message.h"

#include "autograph/aes.h"

bool decrypt_message(unsigned char *plaintext, const unsigned char *key,
                     const unsigned char *message,
                     const unsigned long long message_size) {
  const unsigned int index =
      (message[0] << 24) | (message[1] << 16) | (message[2] << 8) | message[3];
  return aes_decrypt(plaintext, key, index, message + 4, message_size - 4);
}
