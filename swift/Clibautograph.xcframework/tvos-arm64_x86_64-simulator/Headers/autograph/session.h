#ifndef AUTOGRAPH_SESSION_H
#define AUTOGRAPH_SESSION_H

#ifdef __cplusplus
extern "C" {
#endif

int autograph_decrypt(unsigned char *plaintext, unsigned char *plaintext_size,
                      unsigned char *message_index,
                      unsigned char *decrypt_index, unsigned char *skipped_keys,
                      unsigned char *key, const unsigned char *message,
                      const unsigned int message_size);

int autograph_encrypt(unsigned char *message, unsigned char *index,
                      unsigned char *key, const unsigned char *plaintext,
                      const unsigned int plaintext_size);

int autograph_sign_data(unsigned char *signature,
                        const unsigned char *our_private_key,
                        const unsigned char *their_public_key,
                        const unsigned char *data,
                        const unsigned int data_size);

int autograph_sign_identity(unsigned char *signature,
                            const unsigned char *our_private_key,
                            const unsigned char *their_public_key);

int autograph_subject(unsigned char *subject,
                      const unsigned char *their_public_key,
                      const unsigned char *data, const unsigned int data_size);

int autograph_verify_data(const unsigned char *their_public_key,
                          const unsigned char *certificates,
                          const unsigned int certificate_count,
                          const unsigned char *data,
                          const unsigned int data_size);

int autograph_verify_identity(const unsigned char *their_public_key,
                              const unsigned char *certificates,
                              const unsigned int certificate_count);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
