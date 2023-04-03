#pragma once

#include "types.hpp"

namespace autograph {

HandshakeFunction create_handshake(
    const bool is_initiator, const unsigned char *our_identity_private_key,
    const unsigned char *our_identity_public_key,
    unsigned char *our_ephemeral_private_key,
    const unsigned char *our_ephemeral_public_key);

Party create_party(bool is_initiator, const unsigned char *identity_private_key,
                   const unsigned char *identity_public_key,
                   unsigned char *ephemeral_private_key,
                   const unsigned char *ephemeral_public_key);

SafetyNumberFunction create_safety_number(
    const unsigned char *our_identity_key);

SessionFunction create_session(const unsigned char *our_private_key,
                               const unsigned char *their_public_key,
                               const unsigned char *transcript,
                               const unsigned char *our_secret_key,
                               const unsigned char *their_secret_key);

}  // namespace autograph
