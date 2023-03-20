#pragma once

#include "crypto.h"

VerifyFunction create_verify(const Chunk &our_private_key,
                             const Chunk &their_public_key);
