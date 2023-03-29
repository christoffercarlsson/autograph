#pragma once

#include "types.h"

namespace autograph {

HandshakeFunction create_handshake(bool is_initiator,
                                   const KeyPair &our_key_pair,
                                   const Chunk &our_ephemeral_private_key,
                                   const Chunk &our_ephemeral_public_key);

}
