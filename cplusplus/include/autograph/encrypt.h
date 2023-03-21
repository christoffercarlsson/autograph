#pragma once

#include "types.h"

Chunk encrypt(const Chunk &key, const uint32_t index, const Chunk &plaintext);
