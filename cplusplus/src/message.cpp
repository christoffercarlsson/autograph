#include <string.h>

#include "autograph.h"
#include "constants.h"
#include "external.h"
#include "helpers.h"

extern "C" {

size_t calculate_padded_size(const size_t plaintext_size) {
  return plaintext_size + PADDING_BLOCK_SIZE -
         (plaintext_size % PADDING_BLOCK_SIZE);
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

uint32_t get_index(const uint8_t *nonce) {
  return get_uint32(nonce, NONCE_SIZE - 4);
}

void set_index(uint8_t *nonce, const uint32_t index) {
  set_uint32(nonce, NONCE_SIZE - 4, index);
}

bool increment_nonce(uint8_t *nonce) {
  size_t offset = NONCE_SIZE - 4;
  uint32_t index = get_uint32(nonce, offset);
  if (index == UINT32_MAX) {
    return false;
  }
  set_uint32(nonce, offset, index + 1);
  return true;
}

size_t autograph_plaintext_size(const size_t ciphertext_size) {
  return ciphertext_size - TAG_SIZE;
}

size_t autograph_ciphertext_size(const size_t plaintext_size) {
  return calculate_padded_size(plaintext_size) + TAG_SIZE;
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
  if (encrypt(ciphertext, key, nonce, padded, padded_size)) {
    *index = get_index(nonce);
    return true;
  }
  return true;
}

bool decrypt_ciphertext(uint8_t *plaintext, size_t *plaintext_size,
                        const uint8_t *key, const uint8_t *nonce,
                        const uint8_t *ciphertext,
                        const size_t ciphertext_size) {
  if (decrypt(plaintext, key, nonce, ciphertext, ciphertext_size)) {
    return unpad(plaintext_size, plaintext,
                 autograph_plaintext_size(ciphertext_size));
  }
  return false;
}

bool decrypt_skipped(uint32_t *index, uint8_t *plaintext,
                     size_t *plaintext_size, const uint8_t *key,
                     uint32_t *skipped_indexes,
                     const uint16_t skipped_indexes_count,
                     const uint8_t *ciphertext, const size_t ciphertext_size) {
  uint8_t nonce[NONCE_SIZE];
  zeroize(nonce, NONCE_SIZE);
  for (uint16_t i = 0; i < skipped_indexes_count; i++) {
    if (skipped_indexes[i] == 0) {
      continue;
    }
    set_index(nonce, skipped_indexes[i]);
    if (decrypt_ciphertext(plaintext, plaintext_size, key, nonce, ciphertext,
                           ciphertext_size)) {
      *index = skipped_indexes[i];
      skipped_indexes[i] = 0;
      return true;
    }
  }
  return false;
}

bool skip_index(uint32_t *skipped_indexes, const uint16_t skipped_indexes_count,
                const uint8_t *nonce) {
  uint32_t index = get_index(nonce);
  for (uint16_t i = 0; i < skipped_indexes_count; i++) {
    if (skipped_indexes[i] == 0) {
      skipped_indexes[i] = index;
      return true;
    }
  }
  return false;
}

bool autograph_decrypt(uint32_t *index, uint8_t *plaintext,
                       size_t *plaintext_size, const uint8_t *key,
                       uint8_t *nonce, uint32_t *skipped_indexes,
                       const uint16_t skipped_indexes_count,
                       const uint8_t *ciphertext,
                       const size_t ciphertext_size) {
  bool success =
      decrypt_skipped(index, plaintext, plaintext_size, key, skipped_indexes,
                      skipped_indexes_count, ciphertext, ciphertext_size);
  while (!success) {
    if (!increment_nonce(nonce)) {
      return false;
    }
    *index = get_index(nonce);
    success = decrypt_ciphertext(plaintext, plaintext_size, key, nonce,
                                 ciphertext, ciphertext_size);
    if (!success &&
        !skip_index(skipped_indexes, skipped_indexes_count, nonce)) {
      return false;
    }
  }
  return success;
}

}  // extern "C"

namespace Autograph {

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

std::tuple<bool, uint32_t, Bytes> encrypt(const SecretKey &key, Nonce &nonce,
                                          const Bytes &plaintext) {
  uint32_t index;
  Bytes ciphertext = createCiphertext(plaintext);
  bool success =
      autograph_encrypt(&index, ciphertext.data(), key.data(), nonce.data(),
                        plaintext.data(), plaintext.size());
  return {success, index, ciphertext};
}

std::tuple<bool, uint32_t, Bytes> decrypt(const SecretKey &key, Nonce &nonce,
                                          SkippedIndexes &skippedIndexes,
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
  return {success, index, plaintext};
}

}  // namespace Autograph
