#pragma once

#include "types.h"

SecretKeys derive_secret_keys(bool is_initiator,
                              const KeyPair &our_ephemeral_key_pair,
                              const Chunk &their_ephemeral_public_key);
