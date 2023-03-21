#pragma once

#include "types.h"

VerifyFunction create_verify(const Chunk &their_identity_key,
                             const DecryptFunction &decrypt);
