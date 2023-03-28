#include "autograph/aes.h"

#include "sodium.h"

void index_to_nonce(unsigned char *nonce, const unsigned int index) {
  sodium_memzero(nonce, crypto_aead_aes256gcm_NPUBBYTES);
  nonce[crypto_aead_aes256gcm_NPUBBYTES - 4] = (index >> 24) & 0xFF;
  nonce[crypto_aead_aes256gcm_NPUBBYTES - 3] = (index >> 16) & 0xFF;
  nonce[crypto_aead_aes256gcm_NPUBBYTES - 2] = (index >> 8) & 0xFF;
  nonce[crypto_aead_aes256gcm_NPUBBYTES - 1] = index & 0xFF;
}

bool aes_decrypt(unsigned char *plaintext, const unsigned char *key,
                 const unsigned int index, const unsigned char *ciphertext,
                 const unsigned long long ciphertext_size) {
  unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
  index_to_nonce(nonce, index);
  int result = crypto_aead_aes256gcm_decrypt(
      plaintext, NULL, NULL, ciphertext, ciphertext_size, NULL, 0, nonce, key);
  return result == 0;
}

bool aes_encrypt(unsigned char *ciphertext, const unsigned char *key,
                 const unsigned int index, const unsigned char *plaintext,
                 const unsigned long long plaintext_size) {
  unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
  index_to_nonce(nonce, index);
  int result = crypto_aead_aes256gcm_encrypt(
      ciphertext, NULL, plaintext, plaintext_size, NULL, 0, NULL, nonce, key);
  return result == 0;
}
