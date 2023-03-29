#pragma once

#include "types.h"

namespace autograph {

Party create_party(bool is_initiator, const KeyPair &identity_key_pair);

}  // namespace autograph
