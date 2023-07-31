#include "session.h"

#include <string.h>

#include "private.h"

void autograph_subject(unsigned char *subject,
                       const unsigned char *their_public_key,
                       const unsigned char *data,
                       const unsigned long long data_size) {
  if (data_size > 0) {
    memmove(subject, data, data_size);
  }
  memmove(subject + data_size, their_public_key, 32);
}

unsigned long long autograph_subject_size(const unsigned long long data_size) {
  return 32 + data_size;
}

int autograph_certify(unsigned char *signature,
                      const unsigned char *our_private_key,
                      const unsigned char *their_public_key,
                      const unsigned char *data,
                      const unsigned long long data_size) {
  const unsigned long long subject_size = autograph_subject_size(data_size);
  unsigned char subject[subject_size];
  autograph_subject(subject, their_public_key, data, data_size);
  return autograph_crypto_sign(signature, our_private_key, subject,
                               subject_size) == 0
             ? 0
             : -1;
}

int autograph_verify(const unsigned char *their_public_key,
                     const unsigned char *certificates,
                     const unsigned long long certificate_count,
                     const unsigned char *data,
                     const unsigned long long data_size) {
  if (certificates == NULL || certificate_count == 0) {
    return -1;
  }
  const unsigned long long subject_size = autograph_subject_size(data_size);
  unsigned char subject[subject_size];
  autograph_subject(subject, their_public_key, data, data_size);
  for (unsigned long long i = 0; i < certificate_count; i++) {
    const unsigned char *certificate = certificates + i * 96;
    int verify_result = autograph_crypto_verify(certificate, subject,
                                                subject_size, certificate + 32);
    if (verify_result != 0) {
      return -1;
    }
  }
  return 0;
}

int autograph_decrypt(unsigned char *plaintext, const unsigned char *key,
                      const unsigned char *message,
                      const unsigned long long message_size) {
  const unsigned int index =
      (message[0] << 24) | (message[1] << 16) | (message[2] << 8) | message[3];
  return autograph_crypto_decrypt(plaintext, key, index, message + 4,
                                  message_size - 4);
}

int autograph_encrypt(unsigned char *message, const unsigned char *key,
                      const unsigned int index, const unsigned char *plaintext,
                      const unsigned long long plaintext_size) {
  int result = autograph_crypto_encrypt(message + 4, key, index, plaintext,
                                        plaintext_size);
  if (result != 0) {
    return -1;
  }
  message[0] = (index >> 24) & 0xFF;
  message[1] = (index >> 16) & 0xFF;
  message[2] = (index >> 8) & 0xFF;
  message[3] = index & 0xFF;
  return 0;
}

int autograph_session(const unsigned char *transcript,
                      const unsigned char *their_identity_key,
                      const unsigned char *their_secret_key,
                      const unsigned char *ciphertext) {
  unsigned char signature[64];
  int decrypt_result =
      autograph_crypto_decrypt(signature, their_secret_key, 0, ciphertext, 80);
  if (decrypt_result != 0) {
    return -1;
  }
  return autograph_crypto_verify(their_identity_key, transcript, 128,
                                 signature) == 0
             ? 0
             : -1;
}
