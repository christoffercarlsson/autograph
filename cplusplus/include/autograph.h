#pragma once

#include "autograph/types.h"

namespace autograph {

const unsigned int HANDSHAKE_SIZE = 80;
const unsigned int MESSAGE_EXTRA_SIZE = 20;
const unsigned int PRIVATE_KEY_SIZE = 32;
const unsigned int PUBLIC_KEY_SIZE = 32;
const unsigned int SAFETY_NUMBER_SIZE = 60;
const unsigned int SIGNATURE_SIZE = 64;

Party create_initiator(unsigned char* ephemeral_public_key,
                       const unsigned char* private_key,
                       const unsigned char* public_key);

Party create_responder(unsigned char* ephemeral_public_key,
                       const unsigned char* private_key,
                       const unsigned char* public_key);

void init();

void generate_key_pair(unsigned char* private_key, unsigned char* public_key);

}  // namespace autograph
