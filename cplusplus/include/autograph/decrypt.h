#pragma once

#include "types.h"

Chunk decrypt(const Chunk &key, const uint32_t index, const Chunk &ciphertext);
