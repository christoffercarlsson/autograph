#include "constants.hpp"
#include "crypto.hpp"
#include "sodium.h"

namespace autograph {

void index_to_nonce(unsigned char *nonce, const unsigned int index) {
  nonce[CHACHA_NONCE_SIZE - 4] = (index >> 24) & 0xFF;
  nonce[CHACHA_NONCE_SIZE - 3] = (index >> 16) & 0xFF;
  nonce[CHACHA_NONCE_SIZE - 2] = (index >> 8) & 0xFF;
  nonce[CHACHA_NONCE_SIZE - 1] = index & 0xFF;
}

bool decrypt(unsigned char *plaintext, const unsigned char *key,
             const unsigned int index, const unsigned char *ciphertext,
             const unsigned long long ciphertext_size) {
  unsigned char nonce[CHACHA_NONCE_SIZE];
  sodium_memzero(nonce, CHACHA_NONCE_SIZE);
  index_to_nonce(nonce, index);
  return crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, NULL, NULL,
                                                   ciphertext, ciphertext_size,
                                                   NULL, 0, nonce, key) == 0;
}

bool encrypt(unsigned char *ciphertext, const unsigned char *key,
             const unsigned int index, const unsigned char *plaintext,
             const unsigned long long plaintext_size) {
  unsigned char nonce[CHACHA_NONCE_SIZE];
  sodium_memzero(nonce, CHACHA_NONCE_SIZE);
  index_to_nonce(nonce, index);
  return crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, plaintext,
                                                   plaintext_size, NULL, 0,
                                                   NULL, nonce, key) == 0;
}

}  // namespace autograph
