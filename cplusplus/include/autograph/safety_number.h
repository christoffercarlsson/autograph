#pragma once

#include "types.h"

namespace autograph {

SafetyNumberFunction create_safety_number(
    const unsigned char* our_identity_key);

}  // namespace autograph
