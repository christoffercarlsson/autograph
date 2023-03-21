#pragma once

#include "types.h"

bool verify_transcript(const Chunk &transcript, const Chunk &their_identity_key,
                       const Chunk &their_secret_key, const Chunk &ciphertext);
