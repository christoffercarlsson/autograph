#include <vector>

#include "constants.hpp"
#include "crypto.hpp"
#include "sodium.h"
#include "types.hpp"

namespace autograph {

Bytes index_to_nonce(const unsigned int index) {
  Bytes nonce(CHACHA_NONCE_SIZE);
  nonce[CHACHA_NONCE_SIZE - 4] = (index >> 24) & 0xFF;
  nonce[CHACHA_NONCE_SIZE - 3] = (index >> 16) & 0xFF;
  nonce[CHACHA_NONCE_SIZE - 2] = (index >> 8) & 0xFF;
  nonce[CHACHA_NONCE_SIZE - 1] = index & 0xFF;
  return std::move(nonce);
}

bool decrypt(unsigned char *plaintext, const unsigned char *key,
             const unsigned int index, const unsigned char *ciphertext,
             const unsigned long long ciphertext_size) {
  auto nonce = index_to_nonce(index);
  return crypto_aead_chacha20poly1305_ietf_decrypt(
             plaintext, NULL, NULL, ciphertext, ciphertext_size, NULL, 0,
             nonce.data(), key) == 0;
}

bool encrypt(unsigned char *ciphertext, const unsigned char *key,
             const unsigned int index, const unsigned char *plaintext,
             const unsigned long long plaintext_size) {
  auto nonce = index_to_nonce(index);
  return crypto_aead_chacha20poly1305_ietf_encrypt(
             ciphertext, NULL, plaintext, plaintext_size, NULL, 0, NULL,
             nonce.data(), key) == 0;
}

}  // namespace autograph
