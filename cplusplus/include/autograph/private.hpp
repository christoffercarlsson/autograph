#pragma once

#include "constants.hpp"
#include "types.hpp"

namespace autograph {

HandshakeFunction create_handshake(const bool is_initiator,
                                   const KeyPair &identity_key_pair,
                                   KeyPair &ephemeral_key_pair);

Party create_party(const bool is_initiator, const KeyPair &identity_key_pair,
                   KeyPair &ephemeral_key_pair);

SafetyNumberFunction create_safety_number(const ByteVector &our_identity_key);

SessionFunction create_session(const ByteVector &our_private_key,
                               const ByteVector &their_public_key,
                               const ByteVector &transcript,
                               const ByteVector &our_secret_key,
                               const ByteVector &their_secret_key);

}  // namespace autograph
