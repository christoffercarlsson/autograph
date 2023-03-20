#pragma once

#include "create_calculate_safety_number.h"
#include "create_handshake.h"
#include "generate_ephemeral_key_pair.h"

Party create_party(bool is_initiator, const KeyPair &identity_key_pair);
