#pragma once

#include "types.h"

HandshakeFunction create_handshake(bool is_initiator,
                                   const KeyPair &our_key_pair,
                                   const KeyPair &our_ephemeral_key_pair);
