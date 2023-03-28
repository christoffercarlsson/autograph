#include "autograph/encrypt_message.h"

#include "autograph/aes.h"

unsigned int index = 0;

bool encrypt_message(unsigned char *ciphertext, const unsigned char *key,
                     const unsigned char *plaintext,
                     const unsigned long long plaintext_size) {
  index++;
  bool success =
      aes_encrypt(ciphertext + 4, key, index, plaintext, plaintext_size);
  if (!success) {
    return false;
  }
  ciphertext[0] = (index >> 24) & 0xFF;
  ciphertext[1] = (index >> 16) & 0xFF;
  ciphertext[2] = (index >> 8) & 0xFF;
  ciphertext[3] = index & 0xFF;
  return true;
}
