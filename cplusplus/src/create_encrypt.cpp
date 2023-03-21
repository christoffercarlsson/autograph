#include "autograph/create_encrypt.h"

#include "autograph/encrypt.h"

EncryptFunction create_encrypt(const Chunk &our_secret_key) {
  uint32_t index = 0;
  auto encrypt_function = [&our_secret_key, &index](const Chunk &plaintext) {
    index++;
    Chunk ciphertext = encrypt(our_secret_key, index, plaintext);
    return std::move(ciphertext);
  };
  return std::move(encrypt_function);
}
