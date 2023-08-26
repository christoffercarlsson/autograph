#ifndef AUTOGRAPH_KEY_EXCHANGE_H
#define AUTOGRAPH_KEY_EXCHANGE_H

#ifdef __cplusplus
extern "C" {
#endif

int autograph_key_exchange(unsigned char *transcript, unsigned char *handshake,
                           unsigned char *our_secret_key,
                           unsigned char *their_secret_key,
                           const unsigned int is_initiator,
                           const unsigned char *our_private_identity_key,
                           const unsigned char *our_public_identity_key,
                           unsigned char *our_private_ephemeral_key,
                           const unsigned char *our_public_ephemeral_key,
                           const unsigned char *their_public_identity_key,
                           const unsigned char *their_public_ephemeral_key);

int autograph_key_exchange_signature(
    unsigned char *handshake, unsigned char *our_secret_key,
    unsigned char *their_secret_key, const unsigned int is_initiator,
    const unsigned char *our_signature,
    unsigned char *our_private_ephemeral_key,
    const unsigned char *their_public_ephemeral_key);

int autograph_key_exchange_transcript(unsigned char *transcript,
                                      const unsigned int is_initiator,
                                      const unsigned char *our_identity_key,
                                      const unsigned char *our_ephemeral_key,
                                      const unsigned char *their_identity_key,
                                      const unsigned char *their_ephemeral_key);

int autograph_key_exchange_verify(const unsigned char *transcript,
                                  const unsigned char *their_identity_key,
                                  const unsigned char *their_secret_key,
                                  const unsigned char *ciphertext);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
