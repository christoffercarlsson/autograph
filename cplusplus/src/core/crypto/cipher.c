#include <string.h>

#include "private.h"
#include "sizes.h"
#include "sodium.h"

int autograph_crypto_decrypt(unsigned char *plaintext,
                             unsigned char *plaintext_size,
                             const unsigned char *key,
                             const unsigned char *ciphertext,
                             const unsigned int ciphertext_size) {
  unsigned char nonce[12];
  sodium_memzero(nonce, 12);
  if (crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, NULL, NULL,
                                                ciphertext, ciphertext_size,
                                                NULL, 0, nonce, key) != 0) {
    return -1;
  }
  size_t unpadded_size;
  if (sodium_unpad(&unpadded_size, plaintext,
                   autograph_plaintext_size(ciphertext_size), 16) != 0) {
    return -1;
  }
  if (plaintext_size != NULL) {
    plaintext_size[0] = (unpadded_size >> 24) & 0xFF;
    plaintext_size[1] = (unpadded_size >> 16) & 0xFF;
    plaintext_size[2] = (unpadded_size >> 8) & 0xFF;
    plaintext_size[3] = unpadded_size & 0xFF;
  }
  return 0;
}

int autograph_crypto_encrypt(unsigned char *ciphertext,
                             const unsigned char *key,
                             const unsigned char *plaintext,
                             const unsigned int plaintext_size) {
  unsigned int padded_size = autograph_ciphertext_size(plaintext_size) - 16;
  unsigned char padded[padded_size];
  memmove(padded, plaintext, plaintext_size);
  if (sodium_pad(NULL, padded, plaintext_size, 16, padded_size) != 0) {
    return -1;
  }
  unsigned char nonce[12];
  sodium_memzero(nonce, 12);
  return crypto_aead_chacha20poly1305_ietf_encrypt(
      ciphertext, NULL, padded, padded_size, NULL, 0, NULL, nonce, key);
}
