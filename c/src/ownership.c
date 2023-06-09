#include <string.h>

#include "autograph.h"
#include "crypto.h"

unsigned long long calculate_subject_size(
    const unsigned char *message, const unsigned long long message_size) {
  if (message != NULL && message_size > 0) {
    return 32 + message_size - 20;
  }
  return 32;
}

int calculate_subject(unsigned char *subject,
                      const unsigned long long subject_size,
                      const unsigned char *their_public_key,
                      const unsigned char *their_secret_key,
                      const unsigned char *message,
                      const unsigned long long message_size) {
  if (subject_size > 32) {
    int decrypt_result = autograph_decrypt(subject, their_secret_key, message,
                                           message_size) == 0;
    if (decrypt_result != 0) {
      return -1;
    }
    memmove(subject + subject_size - 32, their_public_key, 32);
  } else {
    memmove(subject, their_public_key, 32);
  }
  return 0;
}

int autograph_certify(unsigned char *signature,
                      const unsigned char *our_private_key,
                      const unsigned char *their_public_key,
                      const unsigned char *their_secret_key,
                      const unsigned char *message,
                      const unsigned long long message_size) {
  const unsigned long long subject_size =
      calculate_subject_size(message, message_size);
  unsigned char subject[subject_size];
  int subject_result =
      calculate_subject(subject, subject_size, their_public_key,
                        their_secret_key, message, message_size);
  if (subject_result != 0) {
    return -1;
  }
  return sign(signature, our_private_key, subject, subject_size) == 0 ? 0 : -1;
}

int autograph_verify(const unsigned char *their_public_key,
                     const unsigned char *their_secret_key,
                     const unsigned char *certificates,
                     const unsigned long long certificate_count,
                     const unsigned char *message,
                     const unsigned long long message_size) {
  if (certificates == NULL || certificate_count == 0) {
    return -1;
  }
  const unsigned long long subject_size =
      calculate_subject_size(message, message_size);
  unsigned char subject[subject_size];
  int subject_result =
      calculate_subject(subject, subject_size, their_public_key,
                        their_secret_key, message, message_size);
  if (subject_result != 0) {
    return -1;
  }
  for (unsigned long long i = 0; i < certificate_count; i++) {
    const unsigned char *certificate = certificates + i * 96;
    int verify_result =
        verify(certificate, subject, subject_size, certificate + 32);
    if (verify_result != 0) {
      return -1;
    }
  }
  return 0;
}
