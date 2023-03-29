#pragma once

#include "autograph/types.h"

namespace autograph {

Party create_initiator(const KeyPair &identity_key_pair);

Party create_responder(const KeyPair &identity_key_pair);

void init();

KeyPair key_pair();

}  // namespace autograph
