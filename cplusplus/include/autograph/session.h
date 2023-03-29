#pragma once

#include "types.h"

namespace autograph {

SessionFunction create_session(const Chunk &our_private_key,
                               const Chunk &their_identity_key,
                               const Chunk &transcript,
                               const Chunk &our_secret_key,
                               const Chunk &their_secret_key);

}
