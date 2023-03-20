#include "autograph/create_decrypt.h"

DecryptFunction create_decrypt(const Chunk &their_secret_key) {
  auto decrypt_function = [&their_secret_key](const Chunk &message) {
    uint32_t index = (message[0] << 24) | (message[1] << 16) |
                     (message[2] << 8) | message[3];
    Chunk ciphertext(message.begin() + 4, message.end());
    Chunk plaintext = decrypt(their_secret_key, index, ciphertext);
    return std::move(plaintext);
  };
  return std::move(decrypt_function);
}
