#ifndef AUTOGRAPH_KEY_PAIR_H
#define AUTOGRAPH_KEY_PAIR_H

#ifdef __cplusplus
extern "C" {
#endif

int autograph_key_pair_ephemeral(unsigned char *private_key,
                                 unsigned char *public_key);

int autograph_key_pair_identity(unsigned char *private_key,
                                unsigned char *public_key);

#ifdef __cplusplus
}  // extern "C"

#include "types.h"

namespace autograph {

KeyPairResult generate_ephemeral_key_pair();

KeyPairResult generate_identity_key_pair();

}  // namespace autograph
#endif

#endif
