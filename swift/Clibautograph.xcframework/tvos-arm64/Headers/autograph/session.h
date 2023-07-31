#ifndef AUTOGRAPH_SESSION_H
#define AUTOGRAPH_SESSION_H

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

int autograph_session(const unsigned char *transcript,
                      const unsigned char *their_identity_key,
                      const unsigned char *their_secret_key,
                      const unsigned char *ciphertext);

void autograph_subject(unsigned char *subject,
                       const unsigned char *their_public_key,
                       const unsigned char *data,
                       const unsigned long long data_size);

unsigned long long autograph_subject_size(const unsigned long long data_size);

int autograph_verify(const unsigned char *their_public_key,
                     const unsigned char *certificates,
                     const unsigned long long certificate_count,
                     const unsigned char *data,
                     const unsigned long long data_size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
