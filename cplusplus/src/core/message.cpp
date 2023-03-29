#include "autograph/core/message.h"

#include "autograph/crypto/aes.h"

int autograph_core_message_decrypt(unsigned char *plaintext,
                                   const unsigned char *key,
                                   const unsigned char *message,
                                   const unsigned long long message_size) {
  const unsigned int index =
      (message[0] << 24) | (message[1] << 16) | (message[2] << 8) | message[3];
  bool success = autograph_crypto_aes_decrypt(plaintext, key, index,
                                              message + 4, message_size - 4);
  return success ? 0 : -1;
}

unsigned int autograph_core_message_encrypt_index = 0;

int autograph_core_message_encrypt(unsigned char *ciphertext,
                                   const unsigned char *key,
                                   const unsigned char *plaintext,
                                   const unsigned long long plaintext_size) {
  autograph_core_message_encrypt_index++;
  bool success = autograph_crypto_aes_encrypt(
      ciphertext + 4, key, autograph_core_message_encrypt_index, plaintext,
      plaintext_size);
  if (!success) {
    return -1;
  }
  ciphertext[0] = (autograph_core_message_encrypt_index >> 24) & 0xFF;
  ciphertext[1] = (autograph_core_message_encrypt_index >> 16) & 0xFF;
  ciphertext[2] = (autograph_core_message_encrypt_index >> 8) & 0xFF;
  ciphertext[3] = autograph_core_message_encrypt_index & 0xFF;
  return 0;
}
