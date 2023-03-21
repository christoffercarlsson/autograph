#pragma once

#include "types.h"

SessionFunction create_session(const Chunk &our_private_key,
                               const Chunk &their_identity_key,
                               const Chunk &transcript,
                               const SecretKeys &secret_keys);
