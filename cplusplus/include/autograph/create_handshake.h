#pragma once

#include "create_session.h"
#include "crypto.h"
#include "derive_secret_keys.h"
#include "get_transcript.h"

HandshakeFunction create_handshake(bool is_initiator,
                                   const KeyPair &our_key_pair,
                                   const KeyPair &our_ephemeral_key_pair);
