#pragma once

#include "types.h"

bool verify_signature(const Chunk &public_key, const Chunk &message,
                      const Chunk &signature);
