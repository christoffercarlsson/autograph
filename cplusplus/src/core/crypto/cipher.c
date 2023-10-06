#include "private.h"
#include "sodium.h"

int autograph_crypto_decrypt(unsigned char *plaintext, const unsigned char *key,
                             const unsigned char *ciphertext,
                             const unsigned long long ciphertext_size) {
  unsigned char nonce[12];
  sodium_memzero(nonce, 12);
  return crypto_aead_chacha20poly1305_ietf_decrypt(
      plaintext, NULL, NULL, ciphertext, ciphertext_size, NULL, 0, nonce, key);
}

int autograph_crypto_encrypt(unsigned char *ciphertext,
                             const unsigned char *key,
                             const unsigned char *plaintext,
                             const unsigned long long plaintext_size) {
  unsigned char nonce[12];
  sodium_memzero(nonce, 12);
  return crypto_aead_chacha20poly1305_ietf_encrypt(
      ciphertext, NULL, plaintext, plaintext_size, NULL, 0, NULL, nonce, key);
}
