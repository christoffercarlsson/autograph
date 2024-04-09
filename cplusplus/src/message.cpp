#include "autograph.h"

namespace Autograph {

Bytes createCiphertext(const Bytes plaintext) {
  size_t size = autograph_ciphertext_size(plaintext.size());
  Bytes ciphertext(size);
  return ciphertext;
}

tuple<bool, uint32_t, Bytes> encrypt(SecretKey &key, Nonce &nonce,
                                     const Bytes &plaintext) {
  uint32_t index;
  Bytes ciphertext = createCiphertext(plaintext);
  bool success =
      autograph_encrypt(&index, ciphertext.data(), key.data(), nonce.data(),
                        plaintext.data(), plaintext.size());
  return make_tuple(success, index, ciphertext);
}

Bytes createPlaintext(const Bytes ciphertext) {
  size_t size = autograph_plaintext_size(ciphertext.size());
  Bytes plaintext(size);
  return plaintext;
}

tuple<bool, uint32_t, Bytes> decrypt(SecretKey &key, Nonce &nonce,
                                     Bytes &skippedIndexes,
                                     const Bytes &ciphertext) {
  uint32_t index;
  Bytes plaintext = createPlaintext(ciphertext);
  size_t plaintextSize = 0;
  bool success = autograph_decrypt(&index, plaintext.data(), &plaintextSize,
                                   key.data(), nonce.data(),
                                   skippedIndexes.data(), skippedIndexes.size(),
                                   ciphertext.data(), ciphertext.size());
  if (success) {
    plaintext.resize(plaintextSize);
  }
  return make_tuple(success, index, plaintext);
}

}  // namespace Autograph
