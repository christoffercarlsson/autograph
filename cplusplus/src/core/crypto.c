#include <string.h>

#include "private.h"
#include "sodium.h"

void autograph_crypto_index_to_nonce(unsigned char *nonce,
                                     const unsigned int index) {
  sodium_memzero(nonce, 12);
  nonce[8] = (index >> 24) & 0xFF;
  nonce[9] = (index >> 16) & 0xFF;
  nonce[10] = (index >> 8) & 0xFF;
  nonce[11] = index & 0xFF;
}

int autograph_crypto_decrypt(unsigned char *plaintext, const unsigned char *key,
                             const unsigned int index,
                             const unsigned char *ciphertext,
                             const unsigned long long ciphertext_size) {
  unsigned char nonce[12];
  autograph_crypto_index_to_nonce(nonce, index);
  return crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, NULL, NULL,
                                                   ciphertext, ciphertext_size,
                                                   NULL, 0, nonce, key) == 0
             ? 0
             : -1;
}

int autograph_crypto_encrypt(unsigned char *ciphertext,
                             const unsigned char *key, const unsigned int index,
                             const unsigned char *plaintext,
                             const unsigned long long plaintext_size) {
  unsigned char nonce[12];
  autograph_crypto_index_to_nonce(nonce, index);
  return crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, plaintext,
                                                   plaintext_size, NULL, 0,
                                                   NULL, nonce, key) == 0
             ? 0
             : -1;
}

int autograph_crypto_diffie_hellman(unsigned char *shared_secret,
                                    const unsigned char *our_private_key,
                                    const unsigned char *their_public_key) {
  return crypto_scalarmult(shared_secret, our_private_key, their_public_key) ==
                 0
             ? 0
             : -1;
}

int autograph_crypto_hash(unsigned char *digest, const unsigned char *message,
                          const unsigned long long message_size,
                          const unsigned int iterations) {
  unsigned char d[64];
  int initial_result = crypto_hash_sha512(digest, message, message_size);
  if (initial_result != 0) {
    return -1;
  }
  for (int i = 1; i < iterations; i++) {
    int result = crypto_hash_sha512(d, digest, 64);
    if (result != 0) {
      return -1;
    }
    memmove(digest, d, 64);
  }
  return 0;
}

int autograph_crypto_kdf_extract(unsigned char *prk, const unsigned char *salt,
                                 const unsigned char *ikm) {
  crypto_auth_hmacsha512_state state;
  crypto_auth_hmacsha512_init(&state, salt, 64);
  crypto_auth_hmacsha512_update(&state, ikm, 32);
  return crypto_auth_hmacsha512_final(&state, prk);
}

int autograph_crypto_kdf_expand(unsigned char *okm, const unsigned char *prk,
                                const unsigned char *context) {
  crypto_auth_hmacsha512_state state;
  crypto_auth_hmacsha512_init(&state, prk, 64);
  crypto_auth_hmacsha512_update(&state, context, 1);
  const unsigned char counter = 1;
  crypto_auth_hmacsha512_update(&state, &counter, 1);
  return crypto_auth_hmacsha512_final(&state, okm);
}

int autograph_crypto_kdf(unsigned char *secret_key, const unsigned char *ikm,
                         const unsigned char *context) {
  unsigned char salt[64];
  unsigned char prk[64];
  unsigned char okm[64];
  sodium_memzero(salt, 64);
  int extract_result = autograph_crypto_kdf_extract(prk, salt, ikm);
  if (extract_result != 0) {
    return -1;
  }
  int expand_result = autograph_crypto_kdf_expand(okm, prk, context);
  if (expand_result != 0) {
    return -1;
  }
  memmove(secret_key, okm, 32);
  return 0;
}

int autograph_crypto_sign(unsigned char *signature,
                          const unsigned char *private_key,
                          const unsigned char *message,
                          const unsigned long long message_size) {
  unsigned char sk[64];
  unsigned char pk[32];
  int seed_result = crypto_sign_seed_keypair(pk, sk, private_key);
  if (seed_result != 0) {
    return -1;
  }
  return crypto_sign_detached(signature, NULL, message, message_size, sk) == 0
             ? 0
             : -1;
}

int autograph_crypto_verify(const unsigned char *public_key,
                            const unsigned char *message,
                            const unsigned long long message_size,
                            const unsigned char *signature) {
  return crypto_sign_verify_detached(signature, message, message_size,
                                     public_key) == 0
             ? 0
             : -1;
}
