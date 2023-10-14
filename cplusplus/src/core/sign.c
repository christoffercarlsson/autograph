#include "sign.h"

#include "private.h"

int autograph_sign_subject(unsigned char *signature,
                           const unsigned char *private_key,
                           const unsigned char *subject,
                           const unsigned int subject_size) {
  return autograph_crypto_sign(signature, private_key, subject, subject_size);
}
