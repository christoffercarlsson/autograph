#include "crypto.h"
#include "sodium.h"

void index_to_nonce(unsigned char *nonce, const unsigned int index) {
  sodium_memzero(nonce, 12);
  nonce[8] = (index >> 24) & 0xFF;
  nonce[9] = (index >> 16) & 0xFF;
  nonce[10] = (index >> 8) & 0xFF;
  nonce[11] = index & 0xFF;
}

int decrypt(unsigned char *plaintext, const unsigned char *key,
            const unsigned int index, const unsigned char *ciphertext,
            const unsigned long long ciphertext_size) {
  unsigned char nonce[12];
  index_to_nonce(nonce, index);
  return crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, NULL, NULL,
                                                   ciphertext, ciphertext_size,
                                                   NULL, 0, nonce, key) == 0
             ? 0
             : -1;
}

int encrypt(unsigned char *ciphertext, const unsigned char *key,
            const unsigned int index, const unsigned char *plaintext,
            const unsigned long long plaintext_size) {
  unsigned char nonce[12];
  index_to_nonce(nonce, index);
  return crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, plaintext,
                                                   plaintext_size, NULL, 0,
                                                   NULL, nonce, key) == 0
             ? 0
             : -1;
}
