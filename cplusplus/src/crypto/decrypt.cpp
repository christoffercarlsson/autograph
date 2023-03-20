#include "autograph/crypto.h"

Chunk decrypt(const Chunk &key, const uint32_t index, const Chunk &ciphertext) {
  Chunk plaintext(ciphertext.size() - crypto_aead_aes256gcm_ABYTES);
  Chunk nonce = index_to_nonce(index);
  int result = crypto_aead_aes256gcm_decrypt(
      plaintext.data(), NULL, NULL, ciphertext.data(), ciphertext.size(), NULL,
      0, nonce.data(), key.data());
  if (result != 0) {
    throw std::runtime_error("Failed to decrypt ciphertext");
  }
  return std::move(plaintext);
}
