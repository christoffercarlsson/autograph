#ifndef AUTOGRAPH_HANDSHAKE_H
#define AUTOGRAPH_HANDSHAKE_H

#ifdef __cplusplus
extern "C" {
#endif

int autograph_handshake(unsigned char *transcript, unsigned char *message,
                        unsigned char *our_secret_key,
                        unsigned char *their_secret_key,
                        const unsigned int is_initiator,
                        const unsigned char *our_private_identity_key,
                        const unsigned char *our_public_identity_key,
                        unsigned char *our_private_ephemeral_key,
                        const unsigned char *our_public_ephemeral_key,
                        const unsigned char *their_public_identity_key,
                        const unsigned char *their_public_ephemeral_key);

int autograph_handshake_signature(
    unsigned char *message, unsigned char *our_secret_key,
    unsigned char *their_secret_key, const unsigned int is_initiator,
    const unsigned char *our_signature,
    unsigned char *our_private_ephemeral_key,
    const unsigned char *their_public_ephemeral_key);

int autograph_transcript(unsigned char *transcript,
                         const unsigned int is_initiator,
                         const unsigned char *our_identity_key,
                         const unsigned char *our_ephemeral_key,
                         const unsigned char *their_identity_key,
                         const unsigned char *their_ephemeral_key);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
