#pragma once

#include "autograph.h"

namespace autograph {

HandshakeFunction create_handshake(const bool is_initiator,
                                   const KeyPair &identity_key_pair,
                                   KeyPair &ephemeral_key_pair);

Party create_party(const bool is_initiator, const KeyPair &identity_key_pair,
                   KeyPair &ephemeral_key_pair);

SafetyNumberFunction create_safety_number(const Bytes &our_identity_key);

SessionFunction create_session(const Bytes &our_private_key,
                               const Bytes &their_public_key,
                               const Bytes &transcript,
                               const Bytes &our_secret_key,
                               const Bytes &their_secret_key);

}  // namespace autograph
