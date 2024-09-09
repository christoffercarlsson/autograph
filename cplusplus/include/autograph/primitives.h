#ifndef AUTOGRAPH_PRIMITIVES_H
#define AUTOGRAPH_PRIMITIVES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t autograph_primitive_identity_private_key_size();

size_t autograph_primitive_identity_public_key_size();

size_t autograph_primitive_signature_size();

bool autograph_primitive_key_pair_identity(uint8_t *key_pair);

bool autograph_primitive_sign(uint8_t *signature, const uint8_t *key_pair,
                              const uint8_t *message,
                              const size_t message_size);

bool autograph_primitive_verify(const uint8_t *public_key,
                                const uint8_t *signature,
                                const uint8_t *message,
                                const size_t message_size);

size_t autograph_primitive_session_private_key_size();

size_t autograph_primitive_session_public_key_size();

size_t autograph_primitive_shared_secret_size();

bool autograph_primitive_key_pair_session(uint8_t *key_pair);

bool autograph_primitive_diffie_hellman(uint8_t *shared_secret,
                                        const uint8_t *our_key_pair,
                                        const uint8_t *their_public_key);

bool autograph_primitive_kdf(uint8_t *key, const uint8_t *shared_secret,
                             const uint8_t *info, const size_t info_size);

size_t autograph_primitive_digest_size();

bool autograph_primitive_hash(uint8_t *digest, const uint8_t *message,
                              const size_t message_size);

size_t autograph_primitive_secret_key_size();

size_t autograph_primitive_nonce_size();

size_t autograph_primitive_tag_size();

bool autograph_primitive_generate_secret_key(uint8_t *key);

bool autograph_primitive_encrypt(uint8_t *ciphertext, const uint8_t *key,
                                 const uint8_t *nonce, const uint8_t *plaintext,
                                 const size_t plaintext_size);

bool autograph_primitive_decrypt(uint8_t *plaintext, const uint8_t *key,
                                 const uint8_t *nonce,
                                 const uint8_t *ciphertext,
                                 const size_t ciphertext_size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
