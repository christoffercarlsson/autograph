#include "autograph.h"
#include "crypto.h"

int autograph_decrypt(unsigned char *plaintext, const unsigned char *key,
                      const unsigned char *message,
                      const unsigned long long message_size) {
  const unsigned int index =
      (message[0] << 24) | (message[1] << 16) | (message[2] << 8) | message[3];
  return decrypt(plaintext, key, index, message + 4, message_size - 4);
}

int autograph_encrypt(unsigned char *message, const unsigned char *key,
                      const unsigned int index, const unsigned char *plaintext,
                      const unsigned long long plaintext_size) {
  int result = encrypt(message + 4, key, index, plaintext, plaintext_size);
  if (result != 0) {
    return -1;
  }
  message[0] = (index >> 24) & 0xFF;
  message[1] = (index >> 16) & 0xFF;
  message[2] = (index >> 8) & 0xFF;
  message[3] = index & 0xFF;
  return 0;
}
