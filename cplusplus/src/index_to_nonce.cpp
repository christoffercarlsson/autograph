#include "autograph/index_to_nonce.h"

#include "sodium.h"

Chunk index_to_nonce(const uint32_t index) {
  Chunk nonce(crypto_aead_aes256gcm_NPUBBYTES);
  nonce.push_back((index >> 24) & 0xFF);
  nonce.push_back((index >> 16) & 0xFF);
  nonce.push_back((index >> 8) & 0xFF);
  nonce.push_back(index & 0xFF);
  return std::move(nonce);
}
