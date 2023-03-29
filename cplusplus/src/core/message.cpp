#include "autograph/core/message.h"

#include "autograph/crypto/aes.h"

bool autograph_core_message_decrypt(unsigned char *plaintext,
                                    const unsigned char *key,
                                    const unsigned char *message,
                                    const unsigned long long message_size) {
  const unsigned int index =
      (message[0] << 24) | (message[1] << 16) | (message[2] << 8) | message[3];
  return autograph_crypto_aes_decrypt(plaintext, key, index, message + 4,
                                      message_size - 4);
}

unsigned int autograph_core_message_encrypt_index = 0;

bool autograph_core_message_encrypt(unsigned char *ciphertext,
                                    const unsigned char *key,
                                    const unsigned char *plaintext,
                                    const unsigned long long plaintext_size) {
  autograph_core_message_encrypt_index++;
  bool success = autograph_crypto_aes_encrypt(
      ciphertext + 4, key, autograph_core_message_encrypt_index, plaintext,
      plaintext_size);
  if (!success) {
    return false;
  }
  ciphertext[0] = (autograph_core_message_encrypt_index >> 24) & 0xFF;
  ciphertext[1] = (autograph_core_message_encrypt_index >> 16) & 0xFF;
  ciphertext[2] = (autograph_core_message_encrypt_index >> 8) & 0xFF;
  ciphertext[3] = autograph_core_message_encrypt_index & 0xFF;
  return true;
}
