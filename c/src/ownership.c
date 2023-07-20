#include <string.h>

#include "autograph.h"
#include "crypto.h"

unsigned long long calculate_subject_size(const unsigned long long data_size) {
  return 32 + data_size;
}

void calculate_subject(unsigned char *subject,
                      const unsigned char *their_public_key,
                      const unsigned char *data,
                      const unsigned long long data_size) {
  if (data_size > 0) {
    memmove(subject, data, data_size);
  }
  memmove(subject + data_size, their_public_key, 32);
}

int autograph_certify(unsigned char *signature,
                      const unsigned char *our_private_key,
                      const unsigned char *their_public_key,
                      const unsigned char *data,
                      const unsigned long long data_size) {
  const unsigned long long subject_size = calculate_subject_size(data_size);
  unsigned char subject[subject_size];
  calculate_subject(subject, their_public_key, data, data_size);
  return sign(signature, our_private_key, subject, subject_size) == 0 ? 0 : -1;
}

int autograph_verify(const unsigned char *their_public_key,
                     const unsigned char *certificates,
                     const unsigned long long certificate_count,
                     const unsigned char *data,
                     const unsigned long long data_size) {
  if (certificates == NULL || certificate_count == 0) {
    return -1;
  }
  const unsigned long long subject_size = calculate_subject_size(data_size);
  unsigned char subject[subject_size];
  calculate_subject(subject, their_public_key, data, data_size);
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
