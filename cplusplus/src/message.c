#include <string.h>

#include "autograph.h"
#include "constants.h"
#include "external.h"

size_t calculate_padded_size(const size_t plaintext_size) {
  return plaintext_size + PADDING_BLOCK_SIZE -
         (plaintext_size % PADDING_BLOCK_SIZE);
}

size_t autograph_ciphertext_size(const size_t plaintext_size) {
  return calculate_padded_size(plaintext_size) + TAG_SIZE;
}

size_t autograph_plaintext_size(const size_t ciphertext_size) {
  return ciphertext_size - TAG_SIZE;
}

void pad(uint8_t *padded, const size_t padded_size, const uint8_t *plaintext,
         const size_t plaintext_size) {
  zeroize(padded, padded_size);
  memmove(padded, plaintext, plaintext_size);
  padded[plaintext_size] = PADDING_BYTE;
}

bool encrypt_plaintext(uint8_t *ciphertext, const uint8_t *key,
                       const uint8_t *nonce, const uint8_t *plaintext,
                       const size_t plaintext_size) {
  size_t padded_size = calculate_padded_size(plaintext_size);
  uint8_t padded[padded_size];
  pad(padded, padded_size, plaintext, plaintext_size);
  return encrypt(ciphertext, key, nonce, padded, padded_size);
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

bool encrypt_fail(uint8_t *key, uint8_t *nonce) {
  zeroize(key, SECRET_KEY_SIZE);
  zeroize(nonce, NONCE_SIZE);
  return false;
}

bool autograph_encrypt(uint32_t *index, uint8_t *ciphertext, uint8_t *key,
                       uint8_t *nonce, const uint8_t *plaintext,
                       const size_t plaintext_size) {
  if (!increment_nonce(nonce)) {
    return encrypt_fail(key, nonce);
  }
  *index = get_uint32(nonce, NONCE_SIZE - 4);
  if (!encrypt_plaintext(ciphertext, key, nonce, plaintext, plaintext_size)) {
    return encrypt_fail(key, nonce);
  }
  return true;
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

size_t get_skipped_index_offset(const uint8_t *skipped_indexes,
                                const size_t skipped_indexes_size) {
  size_t max_offset = skipped_indexes_size - 4;
  if (get_uint32(skipped_indexes, max_offset) > 0) {
    return skipped_indexes_size;
  }
  size_t offset = 0;
  while (offset <= max_offset) {
    if (get_uint32(skipped_indexes, offset) == 0) {
      return offset;
    }
    offset += 4;
  }
  return skipped_indexes_size;
}

bool skip_index(const uint8_t *nonce, uint8_t *skipped_indexes,
                const size_t skipped_indexes_size) {
  size_t offset =
      get_skipped_index_offset(skipped_indexes, skipped_indexes_size);
  if (offset == skipped_indexes_size) {
    return false;
  }
  memmove(skipped_indexes + offset, nonce + NONCE_SIZE - 4, 4);
  return true;
}

size_t get_skipped_index(uint32_t *index, uint8_t *nonce,
                         const uint8_t *skipped_indexes,
                         const size_t skipped_indexes_size,
                         const size_t offset) {
  if (offset == 0) {
    zeroize(nonce, NONCE_SIZE);
  }
  if (offset == skipped_indexes_size) {
    return 0;
  }
  *index = get_uint32(skipped_indexes, offset);
  memmove(nonce + NONCE_SIZE - 4, skipped_indexes + offset, 4);
  return offset + 4;
}

void delete_skipped_index(uint8_t *skipped_indexes,
                          const size_t skipped_indexes_size,
                          const size_t next_offset) {
  size_t offset = next_offset - 4;
  size_t last_offset = skipped_indexes_size - 4;
  if (offset != last_offset) {
    memmove(skipped_indexes + offset, skipped_indexes + last_offset, 4);
  }
  zeroize(skipped_indexes + last_offset, skipped_indexes_size - last_offset);
}

bool decrypt_skipped(uint32_t *index, uint8_t *plaintext,
                     size_t *plaintext_size, const uint8_t *key,
                     uint8_t *skipped_indexes,
                     const size_t skipped_indexes_size,
                     const uint8_t *ciphertext, const size_t ciphertext_size) {
  uint8_t nonce[NONCE_SIZE];
  size_t offset =
      get_skipped_index(index, nonce, skipped_indexes, skipped_indexes_size, 0);
  while (offset < skipped_indexes_size) {
    if (decrypt_ciphertext(plaintext, plaintext_size, key, nonce, ciphertext,
                           ciphertext_size)) {
      delete_skipped_index(skipped_indexes, skipped_indexes_size, offset);
      return true;
    }
    offset = get_skipped_index(index, nonce, skipped_indexes,
                               skipped_indexes_size, offset);
  }
  return false;
}

bool decrypt_fail(uint8_t *key, uint8_t *nonce, uint8_t *skipped_indexes,
                  const size_t skipped_indexes_size) {
  zeroize(key, SECRET_KEY_SIZE);
  zeroize(nonce, NONCE_SIZE);
  zeroize(skipped_indexes, skipped_indexes_size);
  return false;
}

bool autograph_decrypt(uint32_t *index, uint8_t *plaintext,
                       size_t *plaintext_size, uint8_t *key, uint8_t *nonce,
                       uint8_t *skipped_indexes,
                       const size_t skipped_indexes_size,
                       const uint8_t *ciphertext,
                       const size_t ciphertext_size) {
  bool success =
      decrypt_skipped(index, plaintext, plaintext_size, key, skipped_indexes,
                      skipped_indexes_size, ciphertext, ciphertext_size);
  while (!success) {
    if (!increment_nonce(nonce)) {
      return decrypt_fail(key, nonce, skipped_indexes, skipped_indexes_size);
    }
    *index = get_uint32(nonce, NONCE_SIZE - 4);
    success = decrypt_ciphertext(plaintext, plaintext_size, key, nonce,
                                 ciphertext, ciphertext_size);
    if (!skip_index(nonce, skipped_indexes, skipped_indexes_size)) {
      return decrypt_fail(key, nonce, skipped_indexes, skipped_indexes_size);
    }
  }
  return true;
}
