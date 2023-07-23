#ifndef AUTOGRAPH_INTERNAL_H
#define AUTOGRAPH_INTERNAL_H

#include "autograph.h"

namespace autograph {

SignFunction create_safe_sign(const SignFunction sign);

HandshakeFunction create_handshake(const bool is_initiator,
                                   const SignFunction sign,
                                   const Bytes identity_public_key);

Party create_party(const bool is_initiator, const SignFunction sign,
                   const Bytes identity_public_key);

SafetyNumberFunction create_safety_number(const Bytes our_identity_key);

SessionFunction create_session(const SignFunction sign,
                               const Bytes their_public_key,
                               const Bytes transcript,
                               const Bytes our_secret_key,
                               const Bytes their_secret_key);

}  // namespace autograph

#endif
