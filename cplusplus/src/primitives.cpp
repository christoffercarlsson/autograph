#include "primitives.h"

#include "autograph.h"
#include "sodium.h"

constexpr size_t IDENTITY_PRIVATE_KEY_SIZE = 32;
constexpr size_t IDENTITY_PUBLIC_KEY_SIZE = 32;
constexpr size_t SIGNATURE_SIZE = 64;

constexpr size_t SESSION_PRIVATE_KEY_SIZE = 32;
constexpr size_t SESSION_PUBLIC_KEY_SIZE = 32;
constexpr size_t SHARED_SECRET_SIZE = 32;

constexpr size_t DIGEST_SIZE = 64;

constexpr size_t SECRET_KEY_SIZE = 32;
constexpr size_t NONCE_SIZE = 12;
constexpr size_t TAG_SIZE = 16;

extern "C" {

#ifndef AUTOGRAPH_CUSTOM_PRIMITIVES

bool autograph_ready() { return sodium_init() >= 0; }

size_t autograph_primitive_identity_private_key_size() {
  return IDENTITY_PRIVATE_KEY_SIZE;
}

size_t autograph_primitive_identity_public_key_size() {
  return IDENTITY_PUBLIC_KEY_SIZE;
}

size_t autograph_primitive_signature_size() { return SIGNATURE_SIZE; }

bool autograph_primitive_key_pair_identity(uint8_t *key_pair) {
  uint8_t public_key[autograph_identity_public_key_size()];
  return crypto_sign_keypair(public_key, key_pair) == 0;
}

bool autograph_primitive_sign(uint8_t *signature, const uint8_t *key_pair,
                              const uint8_t *message,
                              const size_t message_size) {
  return crypto_sign_detached(signature, NULL, message, message_size,
                              key_pair) == 0;
}

bool autograph_primitive_verify(const uint8_t *public_key,
                                const uint8_t *signature,
                                const uint8_t *message,
                                const size_t message_size) {
  return crypto_sign_verify_detached(signature, message, message_size,
                                     public_key) == 0;
}

size_t autograph_primitive_session_private_key_size() {
  return SESSION_PRIVATE_KEY_SIZE;
}

size_t autograph_primitive_session_public_key_size() {
  return SESSION_PUBLIC_KEY_SIZE;
}

size_t autograph_primitive_shared_secret_size() { return SHARED_SECRET_SIZE; }

bool autograph_primitive_key_pair_session(uint8_t *key_pair) {
  return crypto_box_keypair(
             key_pair + autograph_primitive_session_private_key_size(),
             key_pair) == 0;
}

bool autograph_primitive_diffie_hellman(uint8_t *shared_secret,
                                        const uint8_t *our_key_pair,
                                        const uint8_t *their_public_key) {
  return crypto_scalarmult(shared_secret, our_key_pair, their_public_key) == 0;
}

size_t autograph_primitive_digest_size() { return DIGEST_SIZE; }

bool autograph_primitive_hash(uint8_t *digest, const uint8_t *message,
                              const size_t message_size) {
  return crypto_hash_sha512(digest, message, message_size) == 0;
}

extern void zeroize(uint8_t *data, const size_t data_size);

bool autograph_primitive_kdf(uint8_t *key, const uint8_t *shared_secret,
                             const uint8_t *info, const size_t info_size) {
  uint8_t prk[64];
  uint8_t salt[64];
  zeroize(salt, 64);
  if (crypto_kdf_hkdf_sha512_extract(
          prk, salt, sizeof salt, shared_secret,
          autograph_primitive_shared_secret_size()) != 0) {
    return false;
  }
  return crypto_kdf_hkdf_sha512_expand(key, autograph_secret_key_size(),
                                       (char *)info, info_size, prk) == 0;
}

size_t autograph_primitive_secret_key_size() { return SECRET_KEY_SIZE; }

size_t autograph_primitive_nonce_size() { return NONCE_SIZE; }

size_t autograph_primitive_tag_size() { return TAG_SIZE; }

bool autograph_primitive_generate_secret_key(uint8_t *key) {
  crypto_aead_chacha20poly1305_ietf_keygen(key);
  return true;
}

bool autograph_primitive_encrypt(uint8_t *ciphertext, const uint8_t *key,
                                 const uint8_t *nonce, const uint8_t *plaintext,
                                 const size_t plaintext_size) {
  return crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, plaintext,
                                                   plaintext_size, NULL, 0,
                                                   NULL, nonce, key) == 0;
}

bool autograph_primitive_decrypt(uint8_t *plaintext, const uint8_t *key,
                                 const uint8_t *nonce,
                                 const uint8_t *ciphertext,
                                 const size_t ciphertext_size) {
  return crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, NULL, NULL,
                                                   ciphertext, ciphertext_size,
                                                   NULL, 0, nonce, key) == 0;
}

#endif  // !AUTOGRAPH_CUSTOM_PRIMITIVES

}  // extern "C"

namespace Autograph {

bool ready() { return autograph_ready(); }

}  // namespace Autograph
