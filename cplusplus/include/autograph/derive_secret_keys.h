#pragma once

#include "crypto.h"

using SecretKeys = struct {
  Chunk our_secret_key;
  Chunk their_secret_key;
};

SecretKeys derive_secret_keys(bool is_initiator,
                              const KeyPair &our_ephemeral_key_pair,
                              const Chunk &their_ephemeral_public_key);
