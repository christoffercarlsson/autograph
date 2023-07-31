#ifndef AUTOGRAPH_SIGN_H
#define AUTOGRAPH_SIGN_H

#ifdef __cplusplus
extern "C" {
#endif

int autograph_sign(unsigned char *signature, const unsigned char *private_key,
                   const unsigned char *subject,
                   const unsigned long long subject_size);

#ifdef __cplusplus
}  // extern "C"

#include "types.h"

namespace autograph {

SignFunction create_sign(const Bytes identity_private_key);

}  // namespace autograph
#endif

#endif
