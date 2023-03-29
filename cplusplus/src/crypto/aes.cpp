#include "autograph/crypto/aes.h"

#include "sodium.h"

void autograph_crypto_aes_index_to_nonce(unsigned char *nonce,
                                         const unsigned int index) {
  sodium_memzero(nonce, autograph_crypto_aes_NONCE_SIZE);
  nonce[autograph_crypto_aes_NONCE_SIZE - 4] = (index >> 24) & 0xFF;
  nonce[autograph_crypto_aes_NONCE_SIZE - 3] = (index >> 16) & 0xFF;
  nonce[autograph_crypto_aes_NONCE_SIZE - 2] = (index >> 8) & 0xFF;
  nonce[autograph_crypto_aes_NONCE_SIZE - 1] = index & 0xFF;
}

bool autograph_crypto_aes_decrypt(unsigned char *plaintext,
                                  const unsigned char *key,
                                  const unsigned int index,
                                  const unsigned char *ciphertext,
                                  const unsigned long long ciphertext_size) {
  unsigned char nonce[autograph_crypto_aes_NONCE_SIZE];
  autograph_crypto_aes_index_to_nonce(nonce, index);
  int result = crypto_aead_aes256gcm_decrypt(
      plaintext, NULL, NULL, ciphertext, ciphertext_size, NULL, 0, nonce, key);
  return result == 0;
}

bool autograph_crypto_aes_encrypt(unsigned char *ciphertext,
                                  const unsigned char *key,
                                  const unsigned int index,
                                  const unsigned char *plaintext,
                                  const unsigned long long plaintext_size) {
  unsigned char nonce[autograph_crypto_aes_NONCE_SIZE];
  autograph_crypto_aes_index_to_nonce(nonce, index);
  int result = crypto_aead_aes256gcm_encrypt(
      ciphertext, NULL, plaintext, plaintext_size, NULL, 0, NULL, nonce, key);
  return result == 0;
}
