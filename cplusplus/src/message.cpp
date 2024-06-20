#include <string.h>

#include "autograph.h"
#include "primitives.h"
#include "sodium.h"

constexpr uint8_t PADDING_BLOCK_SIZE = 16;
constexpr uint8_t PADDING_BYTE = 128;
constexpr size_t DEFAULT_SKIPPED_INDEXES_COUNT = 128;

extern "C" {

size_t calculate_padded_size(const size_t plaintext_size) {
  return plaintext_size + PADDING_BLOCK_SIZE -
         (plaintext_size % PADDING_BLOCK_SIZE);
}

void zeroize(uint8_t *data, const size_t data_size) {
  sodium_memzero(data, data_size);
}

void pad(uint8_t *padded, const size_t padded_size, const uint8_t *plaintext,
         const size_t plaintext_size) {
  zeroize(padded, padded_size);
  memmove(padded, plaintext, plaintext_size);
  padded[plaintext_size] = PADDING_BYTE;
}

size_t calculate_unpadded_size(const uint8_t *padded,
                               const size_t padded_size) {
  if (padded_size == 0 || (padded_size % PADDING_BLOCK_SIZE) > 0) {
    return 0;
  }
  for (size_t i = padded_size - 1; i >= (padded_size - PADDING_BLOCK_SIZE);
       --i) {
    uint8_t byte = padded[i];
    if (byte == PADDING_BYTE) {
      return i;
    }
    if (byte != 0) {
      return 0;
    }
  }
  return 0;
}

bool unpad(size_t *unpadded_size, const uint8_t *padded,
           const size_t padded_size) {
  size_t size = calculate_unpadded_size(padded, padded_size);
  if (size == 0) {
    return false;
  }
  *unpadded_size = size;
  return true;
}

uint32_t get_uint32(const uint8_t *bytes, const size_t offset) {
  uint32_t number = ((uint32_t)bytes[offset] << 24) |
                    ((uint32_t)bytes[offset + 1] << 16) |
                    ((uint32_t)bytes[offset + 2] << 8) | bytes[offset + 3];
  return number;
}

void set_uint32(uint8_t *bytes, const size_t offset, const uint32_t number) {
  bytes[offset] = (number >> 24) & 0xFF;
  bytes[offset + 1] = (number >> 16) & 0xFF;
  bytes[offset + 2] = (number >> 8) & 0xFF;
  bytes[offset + 3] = number & 0xFF;
}

uint32_t get_index(const uint8_t *nonce) {
  return get_uint32(nonce, autograph_primitive_nonce_size() - 4);
}

void set_index(uint8_t *nonce, const uint32_t index) {
  set_uint32(nonce, autograph_primitive_nonce_size() - 4, index);
}

bool increment_nonce(uint8_t *nonce) {
  size_t offset = autograph_primitive_nonce_size() - 4;
  uint32_t index = get_uint32(nonce, offset);
  if (index == UINT32_MAX) {
    return false;
  }
  set_uint32(nonce, offset, index + 1);
  return true;
}

size_t autograph_plaintext_size(const size_t ciphertext_size) {
  return ciphertext_size - autograph_primitive_tag_size();
}

size_t autograph_ciphertext_size(const size_t plaintext_size) {
  return calculate_padded_size(plaintext_size) + autograph_primitive_tag_size();
}

bool autograph_generate_secret_key(uint8_t *key) {
  return autograph_primitive_generate_secret_key(key);
}

bool autograph_encrypt(uint32_t *index, uint8_t *ciphertext, const uint8_t *key,
                       uint8_t *nonce, const uint8_t *plaintext,
                       const size_t plaintext_size) {
  if (!increment_nonce(nonce)) {
    return false;
  }
  size_t padded_size = calculate_padded_size(plaintext_size);
  uint8_t padded[padded_size];
  pad(padded, padded_size, plaintext, plaintext_size);
  if (autograph_primitive_encrypt(ciphertext, key, nonce, padded,
                                  padded_size)) {
    *index = get_index(nonce);
    return true;
  }
  return true;
}

bool decrypt_ciphertext(uint8_t *plaintext, size_t *plaintext_size,
                        const uint8_t *key, const uint8_t *nonce,
                        const uint8_t *ciphertext,
                        const size_t ciphertext_size) {
  if (autograph_primitive_decrypt(plaintext, key, nonce, ciphertext,
                                  ciphertext_size)) {
    return unpad(plaintext_size, plaintext,
                 autograph_plaintext_size(ciphertext_size));
  }
  return false;
}

bool decrypt_skipped(uint32_t *index, uint8_t *plaintext,
                     size_t *plaintext_size, const uint8_t *key,
                     uint8_t *skipped_indexes,
                     const size_t skipped_indexes_size,
                     const uint8_t *ciphertext, const size_t ciphertext_size) {
  size_t nonce_size = autograph_primitive_nonce_size();
  uint8_t nonce[nonce_size];
  zeroize(nonce, nonce_size);
  for (size_t offset = 0; offset < skipped_indexes_size; offset += 4) {
    *index = get_uint32(skipped_indexes, offset);
    if (*index == 0) {
      continue;  // TODO: Order skipped indexes so that we can break as soon as
                 // possible
    }
    set_index(nonce, *index);
    if (decrypt_ciphertext(plaintext, plaintext_size, key, nonce, ciphertext,
                           ciphertext_size)) {
      set_uint32(skipped_indexes, offset, 0);
      return true;
    }
  }
  return false;
}

bool skip_index(uint8_t *skipped_indexes, const size_t skipped_indexes_size,
                const uint8_t *nonce) {
  uint32_t index = get_index(nonce);
  for (size_t offset = 0; offset < skipped_indexes_size; offset += 4) {
    if (get_uint32(skipped_indexes, offset) == 0) {
      set_uint32(skipped_indexes, offset, index);
      return true;
    }
  }
  return false;
}

bool autograph_decrypt(uint32_t *index, uint8_t *plaintext,
                       size_t *plaintext_size, const uint8_t *key,
                       uint8_t *nonce, uint8_t *skipped_indexes,
                       const size_t skipped_indexes_size,
                       const uint8_t *ciphertext,
                       const size_t ciphertext_size) {
  bool success =
      decrypt_skipped(index, plaintext, plaintext_size, key, skipped_indexes,
                      skipped_indexes_size, ciphertext, ciphertext_size);
  while (!success) {
    if (!increment_nonce(nonce)) {
      return false;
    }
    *index = get_index(nonce);
    success = decrypt_ciphertext(plaintext, plaintext_size, key, nonce,
                                 ciphertext, ciphertext_size);
    if (!success && !skip_index(skipped_indexes, skipped_indexes_size, nonce)) {
      return false;
    }
  }
  return success;
}

size_t autograph_secret_key_size() {
  return autograph_primitive_secret_key_size();
}

size_t autograph_nonce_size() { return autograph_primitive_nonce_size(); }

size_t autograph_skipped_indexes_size(const uint16_t count) {
  return (count == 0 ? DEFAULT_SKIPPED_INDEXES_COUNT : count) * 4;
}

}  // extern "C"

namespace Autograph {

Bytes createSecretKey() {
  Bytes secretKey(autograph_secret_key_size());
  return secretKey;
}

std::tuple<bool, Bytes> generateSecretKey() {
  auto key = createSecretKey();
  bool success = autograph_generate_secret_key(key.data());
  return {success, key};
}

Bytes createNonce() {
  Bytes nonce(autograph_nonce_size());
  zeroize(nonce.data(), nonce.size());
  return nonce;
}

Bytes createSkippedIndexes(const std::optional<uint16_t> count) {
  Bytes indexes(autograph_skipped_indexes_size(count ? *count : 0));
  zeroize(indexes.data(), indexes.size());
  return indexes;
}

Bytes createCiphertext(const Bytes plaintext) {
  size_t size = autograph_ciphertext_size(plaintext.size());
  Bytes ciphertext(size);
  return ciphertext;
}

Bytes createPlaintext(const Bytes ciphertext) {
  size_t size = autograph_plaintext_size(ciphertext.size());
  Bytes plaintext(size);
  return plaintext;
}

std::tuple<bool, uint32_t, Bytes> encrypt(const Bytes &key, Bytes &nonce,
                                          const Bytes &plaintext) {
  uint32_t index = 0;
  Bytes ciphertext = createCiphertext(plaintext);
  bool success =
      autograph_encrypt(&index, ciphertext.data(), key.data(), nonce.data(),
                        plaintext.data(), plaintext.size());
  return {success, index, ciphertext};
}

std::tuple<bool, uint32_t, Bytes> decrypt(const Bytes &key, Bytes &nonce,
                                          Bytes &skippedIndexes,
                                          const Bytes &ciphertext) {
  uint32_t index = 0;
  Bytes plaintext = createPlaintext(ciphertext);
  size_t plaintextSize = 0;
  bool success = autograph_decrypt(&index, plaintext.data(), &plaintextSize,
                                   key.data(), nonce.data(),
                                   skippedIndexes.data(), skippedIndexes.size(),
                                   ciphertext.data(), ciphertext.size());
  if (success) {
    plaintext.resize(plaintextSize);
  }
  return {success, index, plaintext};
}

}  // namespace Autograph
