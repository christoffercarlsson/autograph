#pragma once

#include "autograph/constants.h"
#include "autograph/types.h"

Party create_party(bool is_initiator, const KeyPair &identity_key_pair);

Party generate_party(bool is_initiator);

KeyPair generate_key_pair();

void init();
