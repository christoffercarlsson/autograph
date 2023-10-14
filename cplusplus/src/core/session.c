#include "session.h"

#include <string.h>

#include "numbers.h"
#include "private.h"
#include "sodium.h"

void autograph_increment_index(unsigned char *index) {
  unsigned long long number = autograph_read_uint64(index);
  number++;
  for (int i = 7; i >= 0; i--) {
    index[i] = (unsigned char)(number & 0xFF);
    number >>= 8;
  }
}

int autograph_kdf_ratchet(unsigned char *key, unsigned char *index) {
  unsigned char k[32];
  memmove(k, key, 32);
  autograph_increment_index(index);
  int result = autograph_crypto_kdf(key, k, index);
  sodium_memzero(k, 32);
  return result;
}

int autograph_session_fail(unsigned char *key, unsigned char *skipped_keys,
                           unsigned char *message_index) {
  sodium_memzero(key, 32);
  if (skipped_keys != NULL) {
    sodium_memzero(skipped_keys, 40002);
  }
  sodium_memzero(message_index, 8);
  return -1;
}

unsigned short autograph_skipped_keys_count(const unsigned char *skipped_keys) {
  return ((skipped_keys[0] << 8) | skipped_keys[1]);
}

unsigned short autograph_skipped_keys_offset(const unsigned short i) {
  return 2 + i * 40;
}

int autograph_update_skipped_keys(unsigned char *skipped_keys,
                                  unsigned short count) {
  skipped_keys[0] = (count >> 8) & 0xFF;
  skipped_keys[1] = count & 0xFF;
  unsigned short offset = autograph_skipped_keys_offset(count);
  sodium_memzero(skipped_keys + offset, 40002 - offset);
  return 0;
}

int autograph_delete_skipped_key(unsigned char *skipped_keys,
                                 const unsigned short i) {
  unsigned short new_count = autograph_skipped_keys_count(skipped_keys) - 1;
  if (new_count > 0 && i != new_count) {
    memmove(skipped_keys + autograph_skipped_keys_offset(i),
            skipped_keys + autograph_skipped_keys_offset(new_count), 40);
  }
  return autograph_update_skipped_keys(skipped_keys, new_count);
}

int autograph_decrypt_skipped(unsigned char *plaintext,
                              unsigned char *plaintext_size,
                              unsigned char *message_index,
                              unsigned char *skipped_keys,
                              const unsigned char *message,
                              const unsigned int message_size) {
  unsigned short skipped_count = autograph_skipped_keys_count(skipped_keys);
  if (skipped_count == 0) {
    return 1;
  }
  for (int i = 0; i < skipped_count; i++) {
    unsigned short offset = autograph_skipped_keys_offset(i);
    if (autograph_crypto_decrypt(plaintext, plaintext_size,
                                 skipped_keys + offset + 8, message,
                                 message_size) == 0) {
      memmove(message_index, skipped_keys + offset, 8);
      return autograph_delete_skipped_key(skipped_keys, i) != 0 ? -1 : 0;
    }
  }
  return 1;
}

int autograph_skip_key(unsigned char *key, unsigned char *message_index,
                       unsigned char *skipped_keys) {
  unsigned short new_count = autograph_skipped_keys_count(skipped_keys) + 1;
  unsigned short offset = autograph_skipped_keys_offset(new_count);
  memmove(skipped_keys + offset, message_index, 8);
  memmove(skipped_keys + offset + 8, key, 32);
  return autograph_update_skipped_keys(skipped_keys, new_count);
}

int autograph_decrypt(unsigned char *plaintext, unsigned char *plaintext_size,
                      unsigned char *message_index,
                      unsigned char *decrypt_index, unsigned char *skipped_keys,
                      unsigned char *key, const unsigned char *message,
                      const unsigned int message_size) {
  int result =
      autograph_decrypt_skipped(plaintext, plaintext_size, message_index,
                                skipped_keys, message, message_size);
  if (result < 0) {
    return autograph_session_fail(key, skipped_keys, message_index);
  }
  while (result != 0) {
    if (autograph_kdf_ratchet(key, decrypt_index) != 0) {
      return autograph_session_fail(key, skipped_keys, message_index);
    }
    result = autograph_crypto_decrypt(plaintext, plaintext_size, key, message,
                                      message_size);
    if (result == 0) {
      memmove(message_index, decrypt_index, 8);
    } else {
      if (autograph_skipped_keys_count(skipped_keys) == 1000) {
        return autograph_session_fail(key, skipped_keys, message_index);
      }
      if (autograph_skip_key(key, decrypt_index, skipped_keys) != 0) {
        return autograph_session_fail(key, skipped_keys, message_index);
      }
    }
  }
  return 0;
}

int autograph_encrypt(unsigned char *message, unsigned char *message_index,
                      unsigned char *key, const unsigned char *plaintext,
                      const unsigned int plaintext_size) {
  if (autograph_kdf_ratchet(key, message_index) != 0) {
    return autograph_session_fail(key, NULL, message_index);
  }
  if (autograph_crypto_encrypt(message, key, plaintext, plaintext_size) != 0) {
    return autograph_session_fail(key, NULL, message_index);
  }
  return 0;
}

int autograph_sign_data(unsigned char *signature,
                        const unsigned char *our_private_key,
                        const unsigned char *their_public_key,
                        const unsigned char *data,
                        const unsigned int data_size) {
  unsigned int subject_size = data_size + 32;
  unsigned char subject[subject_size];
  autograph_subject(subject, their_public_key, data, data_size);
  return autograph_crypto_sign(signature, our_private_key, subject,
                               subject_size);
}

int autograph_sign_identity(unsigned char *signature,
                            const unsigned char *our_private_key,
                            const unsigned char *their_public_key) {
  return autograph_sign_data(signature, our_private_key, their_public_key, NULL,
                             0);
}

int autograph_subject(unsigned char *subject,
                      const unsigned char *their_public_key,
                      const unsigned char *data, const unsigned int data_size) {
  if (data_size > 0) {
    memmove(subject, data, data_size);
  }
  memmove(subject + data_size, their_public_key, 32);
  return 0;
}

int autograph_verify_data(const unsigned char *their_public_key,
                          const unsigned char *certificates,
                          const unsigned int certificate_count,
                          const unsigned char *data,
                          const unsigned int data_size) {
  if (certificates == NULL || certificate_count == 0) {
    return -1;
  }
  unsigned int subject_size = data_size + 32;
  unsigned char subject[subject_size];
  autograph_subject(subject, their_public_key, data, data_size);
  for (unsigned int i = 0; i < certificate_count; i++) {
    const unsigned char *certificate = certificates + i * 96;
    int verify_result = autograph_crypto_verify(certificate, subject,
                                                subject_size, certificate + 32);
    if (verify_result != 0) {
      return -1;
    }
  }
  return 0;
}

int autograph_verify_identity(const unsigned char *their_public_key,
                              const unsigned char *certificates,
                              const unsigned int certificate_count) {
  return autograph_verify_data(their_public_key, certificates,
                               certificate_count, NULL, 0);
}
