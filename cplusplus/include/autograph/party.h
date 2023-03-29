#pragma once

#include "types.h"

namespace autograph {

Party party_create(bool is_initiator, const KeyPair &identity_key_pair);

}  // namespace autograph
