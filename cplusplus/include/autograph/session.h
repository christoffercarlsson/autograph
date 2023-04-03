#pragma once

#include "types.h"

namespace autograph {

SessionFunction create_session(const unsigned char* our_private_key,
                               const unsigned char* their_identity_key,
                               const unsigned char* transcript,
                               const unsigned char* our_secret_key,
                               const unsigned char* their_secret_key);

}
