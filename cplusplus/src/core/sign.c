#include "sign.h"

#include "private.h"

int autograph_sign(unsigned char *signature, const unsigned char *private_key,
                   const unsigned char *subject,
                   const unsigned long long subject_size) {
  return sign(signature, private_key, subject, subject_size);
}
