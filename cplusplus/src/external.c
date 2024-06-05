#include "external.h"

#include "autograph.h"
#include "constants.h"
#include "sodium.h"

bool ready() { return sodium_init() >= 0; }

bool encrypt(uint8_t *ciphertext, const uint8_t *key, const uint8_t *nonce,
             const uint8_t *plaintext, const size_t plaintext_size) {
  return crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, plaintext,
                                                   plaintext_size, NULL, 0,
                                                   NULL, nonce, key) == 0;
}

bool decrypt(uint8_t *plaintext, const uint8_t *key, const uint8_t *nonce,
             const uint8_t *ciphertext, const size_t ciphertext_size) {
  return crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, NULL, NULL,
                                                   ciphertext, ciphertext_size,
                                                   NULL, 0, nonce, key) == 0;
}

bool diffie_hellman(uint8_t *shared_secret, const uint8_t *our_key_pair,
                    const uint8_t *their_public_key) {
  return crypto_scalarmult(shared_secret, our_key_pair, their_public_key) == 0;
}

bool key_pair_identity(uint8_t *key_pair) {
  uint8_t public_key[PUBLIC_KEY_SIZE];
  return crypto_sign_keypair(public_key, key_pair) == 0;
}

bool key_pair_session(uint8_t *key_pair) {
  return crypto_box_keypair(key_pair + PRIVATE_KEY_SIZE, key_pair) == 0;
}

bool sign(uint8_t *signature, const uint8_t *key_pair, const uint8_t *message,
          const size_t message_size) {
  return crypto_sign_detached(signature, NULL, message, message_size,
                              key_pair) == 0;
}

bool verify(const uint8_t *public_key, const uint8_t *signature,
            const uint8_t *message, const size_t message_size) {
  return crypto_sign_verify_detached(signature, message, message_size,
                                     public_key) == 0;
}

bool hash(uint8_t *digest, const uint8_t *message, const size_t message_size) {
  return crypto_hash_sha512(digest, message, message_size) == 0;
}

bool hkdf(uint8_t *okm, const size_t okm_size, const uint8_t *ikm,
          const size_t ikm_size, const uint8_t *salt, const size_t salt_size,
          const uint8_t *info, const size_t info_size) {
  uint8_t prk[64];
  if (crypto_kdf_hkdf_sha512_extract(prk, salt, salt_size, ikm, ikm_size) !=
      0) {
    return false;
  }
  return crypto_kdf_hkdf_sha512_expand(okm, okm_size, (char *)info, info_size,
                                       prk) == 0;
}
