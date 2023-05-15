#pragma once

#include "autograph/types.hpp"

namespace autograph {

Party create_initiator(const KeyPair &identity_key_pair,
                       KeyPair &ephemeral_key_pair);

Party create_responder(const KeyPair &identity_key_pair,
                       KeyPair &ephemeral_key_pair);

KeyPair generate_ephemeral_key_pair();

KeyPair generate_identity_key_pair();

void init();

}  // namespace autograph
