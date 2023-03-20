#include "autograph/crypto.h"

Chunk encrypt(const Chunk &key, const uint32_t index, const Chunk &plaintext) {
  Chunk ciphertext(plaintext.size() + crypto_aead_aes256gcm_ABYTES);
  Chunk nonce = index_to_nonce(index);
  int result = crypto_aead_aes256gcm_encrypt(
      ciphertext.data(), NULL, plaintext.data(), plaintext.size(), NULL, 0,
      NULL, nonce.data(), key.data());
  if (result != 0) {
    throw std::runtime_error("Failed to encrypt message");
  }
  return std::move(ciphertext);
}
