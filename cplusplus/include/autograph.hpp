#pragma once

#include "autograph/types.hpp"

namespace autograph {

Party create_initiator(const unsigned char *identity_private_key,
                       const unsigned char *identity_public_key,
                       unsigned char *ephemeral_private_key,
                       const unsigned char *ephemeral_public_key);

Party create_responder(const unsigned char *identity_private_key,
                       const unsigned char *identity_public_key,
                       unsigned char *ephemeral_private_key,
                       const unsigned char *ephemeral_public_key);

bool generate_ephemeral_key_pair(unsigned char *private_key,
                                 unsigned char *public_key);

bool generate_identity_key_pair(unsigned char *private_key,
                                unsigned char *public_key);

bool init();

}  // namespace autograph
