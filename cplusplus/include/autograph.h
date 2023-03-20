#pragma once

namespace autograph {
constexpr unsigned int IDENTITY_SIZE = 64;
constexpr unsigned int PRIVATE_KEY_SIZE = 32;
constexpr unsigned int PUBLIC_KEY_SIZE = 32;
constexpr unsigned int SECRET_KEY_SIZE = 32;
constexpr unsigned int SIGNATURE_SIZE = 64;

#include "autograph/generate_key_pair.h"
#include "autograph/init.h"
#include "autograph/types.h"
}  // namespace autograph
