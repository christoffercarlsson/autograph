#pragma once

#include "types.h"

namespace autograph {

Party create_party(unsigned char* ephemeral_public_key, bool is_initiator,
                   const unsigned char* identity_private_key,
                   const unsigned char* identity_public_key);

}  // namespace autograph
