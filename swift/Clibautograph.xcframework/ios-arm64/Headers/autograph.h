#ifndef AUTOGRAPH_H
#define AUTOGRAPH_H

#ifdef __cplusplus
extern "C" {
#endif

int autograph_certify(unsigned char *signature,
                      const unsigned char *our_private_key,
                      const unsigned char *their_public_key,
                      const unsigned char *data,
                      const unsigned long long data_size);

int autograph_decrypt(unsigned char *plaintext, const unsigned char *key,
                      const unsigned char *message,
                      const unsigned long long message_size);

int autograph_encrypt(unsigned char *message, const unsigned char *key,
                      const unsigned int index, const unsigned char *plaintext,
                      const unsigned long long plaintext_size);

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

unsigned int autograph_handshake_size();

int autograph_init();

int autograph_key_pair_ephemeral(unsigned char *private_key,
                                 unsigned char *public_key);

int autograph_key_pair_identity(unsigned char *private_key,
                                unsigned char *public_key);

unsigned int autograph_message_extra_size();

unsigned int autograph_private_key_size();

unsigned int autograph_public_key_size();

int autograph_safety_number(unsigned char *safety_number,
                            const unsigned char *our_identity_key,
                            const unsigned char *their_identity_key);

unsigned int autograph_safety_number_size();

unsigned int autograph_secret_key_size();

int autograph_sign(unsigned char *signature, const unsigned char *private_key,
                   const unsigned char *subject,
                   const unsigned long long subject_size);

unsigned int autograph_signature_size();

int autograph_session(const unsigned char *transcript,
                      const unsigned char *their_identity_key,
                      const unsigned char *their_secret_key,
                      const unsigned char *ciphertext);

void autograph_subject(unsigned char *subject,
                       const unsigned char *their_public_key,
                       const unsigned char *data,
                       const unsigned long long data_size);

unsigned long long autograph_subject_size(const unsigned long long data_size);

int autograph_transcript(unsigned char *transcript,
                         const unsigned int is_initiator,
                         const unsigned char *our_identity_key,
                         const unsigned char *our_ephemeral_key,
                         const unsigned char *their_identity_key,
                         const unsigned char *their_ephemeral_key);

unsigned int autograph_transcript_size();

int autograph_verify(const unsigned char *their_public_key,
                     const unsigned char *certificates,
                     const unsigned long long certificate_count,
                     const unsigned char *data,
                     const unsigned long long data_size);

#ifdef __cplusplus
}
#endif

#endif
