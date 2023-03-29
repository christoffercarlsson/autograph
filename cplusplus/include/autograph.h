#pragma once

#include "autograph/types.h"

namespace autograph {

const unsigned int HANDSHAKE_SIZE = 80;
const unsigned int PRIVATE_KEY_SIZE = 32;
const unsigned int PUBLIC_KEY_SIZE = 32;
const unsigned int SAFETY_NUMBER_SIZE = 60;
const unsigned int SIGNATURE_SIZE = 64;

Party create_initiator(const KeyPair &identity_key_pair);

Party create_responder(const KeyPair &identity_key_pair);

void init();

KeyPair generate_key_pair();

}  // namespace autograph
