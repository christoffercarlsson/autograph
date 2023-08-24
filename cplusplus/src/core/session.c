#include "session.h"

#include <string.h>

#include "private.h"

int autograph_decrypt(unsigned char *plaintext, const unsigned char *key,
                      const unsigned char *message,
                      const unsigned long long message_size) {
  const unsigned long long index = ((unsigned long long)message[0] << 56) |
                                   ((unsigned long long)message[1] << 48) |
                                   ((unsigned long long)message[2] << 40) |
                                   ((unsigned long long)message[3] << 32) |
                                   ((unsigned long long)message[4] << 24) |
                                   ((unsigned long long)message[5] << 16) |
                                   ((unsigned long long)message[6] << 8) |
                                   (unsigned long long)message[7];
  return autograph_crypto_decrypt(plaintext, key, index, message + 8,
                                  message_size - 8);
}

int autograph_encrypt(unsigned char *message, const unsigned char *key,
                      const unsigned long long index,
                      const unsigned char *plaintext,
                      const unsigned long long plaintext_size) {
  int result = autograph_crypto_encrypt(message + 8, key, index, plaintext,
                                        plaintext_size);
  if (result != 0) {
    return -1;
  }
  message[0] = (index >> 56) & 0xFF;
  message[1] = (index >> 48) & 0xFF;
  message[2] = (index >> 40) & 0xFF;
  message[3] = (index >> 32) & 0xFF;
  message[4] = (index >> 24) & 0xFF;
  message[5] = (index >> 16) & 0xFF;
  message[6] = (index >> 8) & 0xFF;
  message[7] = index & 0xFF;
  return 0;
}

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

int autograph_sign_data(unsigned char *signature,
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

int autograph_sign_identity(unsigned char *signature,
                            const unsigned char *our_private_key,
                            const unsigned char *their_public_key) {
  return autograph_sign_data(signature, our_private_key, their_public_key, NULL,
                             0);
}

int autograph_verify_data(const unsigned char *their_public_key,
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

int autograph_verify_identity(const unsigned char *their_public_key,
                              const unsigned char *certificates,
                              const unsigned long long certificate_count) {
  return autograph_verify_data(their_public_key, certificates,
                               certificate_count, NULL, 0);
}
