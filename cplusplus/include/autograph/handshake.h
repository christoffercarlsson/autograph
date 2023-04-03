#pragma once

#include "types.h"

namespace autograph {

HandshakeFunction create_handshake(
    bool is_initiator, const unsigned char* our_identity_private_key,
    const unsigned char* our_identity_public_key,
    const unsigned char* our_ephemeral_private_key,
    const unsigned char* our_ephemeral_public_key);

}
