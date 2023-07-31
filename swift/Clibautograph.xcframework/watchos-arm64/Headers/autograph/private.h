#ifndef AUTOGRAPH_PRIVATE_H
#define AUTOGRAPH_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif

int autograph_crypto_decrypt(unsigned char *plaintext, const unsigned char *key,
                             const unsigned int index,
                             const unsigned char *ciphertext,
                             const unsigned long long ciphertext_size);

int autograph_crypto_encrypt(unsigned char *ciphertext,
                             const unsigned char *key, const unsigned int index,
                             const unsigned char *plaintext,
                             const unsigned long long plaintext_size);

int autograph_crypto_diffie_hellman(unsigned char *shared_secret,
                                    const unsigned char *our_private_key,
                                    const unsigned char *their_public_key);

int autograph_crypto_hash(unsigned char *digest, const unsigned char *message,
                          const unsigned long long message_size,
                          const unsigned int iterations);

int autograph_crypto_kdf(unsigned char *secret_key, const unsigned char *ikm,
                         const unsigned char *context);

int autograph_crypto_sign(unsigned char *signature,
                          const unsigned char *private_key,
                          const unsigned char *message,
                          const unsigned long long message_size);

int autograph_crypto_verify(const unsigned char *public_key,
                            const unsigned char *message,
                            const unsigned long long message_size,
                            const unsigned char *signature);

#ifdef __cplusplus
}  // extern "C"

#include "types.h"

namespace autograph {

SignFunction create_safe_sign(const SignFunction sign);

HandshakeFunction create_handshake(const bool is_initiator,
                                   const SignFunction sign,
                                   const Bytes identity_public_key);

Party create_party(const bool is_initiator, const SignFunction sign,
                   const Bytes identity_public_key);

SafetyNumberFunction create_safety_number(const Bytes our_identity_key);

SessionFunction create_session(const SignFunction sign,
                               const Bytes their_public_key,
                               const Bytes transcript,
                               const Bytes our_secret_key,
                               const Bytes their_secret_key);

}  // namespace autograph
#endif

#endif
