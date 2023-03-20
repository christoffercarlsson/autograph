#pragma once

#include "types.h"

Chunk get_transcript(bool is_initiator, const KeyPair &our_key_pair,
                     const KeyPair &our_ephemeral_key_pair,
                     const Chunk &their_identity_key,
                     const Chunk &their_ephemeral_public_key);
