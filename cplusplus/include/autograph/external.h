#ifndef AUTOGRAPH_EXTERNAL_H
#define AUTOGRAPH_EXTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool ready();

bool encrypt(uint8_t *ciphertext, const uint8_t *key, const uint8_t *nonce,
             const uint8_t *plaintext, const size_t plaintext_size);

bool decrypt(uint8_t *plaintext, const uint8_t *key, const uint8_t *nonce,
             const uint8_t *ciphertext, const size_t ciphertext_size);

bool diffie_hellman(uint8_t *shared_secret, const uint8_t *our_key_pair,
                    const uint8_t *their_public_key);

bool key_pair_identity(uint8_t *key_pair);

bool key_pair_session(uint8_t *key_pair);

bool sign(uint8_t *signature, const uint8_t *key_pair, const uint8_t *message,
          const size_t message_size);

bool verify(const uint8_t *public_key, const uint8_t *signature,
            const uint8_t *message, const size_t message_size);

bool hash(uint8_t *digest, const uint8_t *message, const size_t message_size);

bool hkdf(uint8_t *okm, const size_t okm_size, const uint8_t *ikm,
          const size_t ikm_size, const uint8_t *salt, const size_t salt_size,
          const uint8_t *info, const size_t info_size);

uint32_t get_uint32(const uint8_t *bytes, const size_t offset);

void set_uint32(uint8_t *bytes, const size_t offset, const uint32_t number);

#ifdef __cplusplus
}
#endif

#endif
