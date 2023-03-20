#pragma once

#include "crypto.h"
#include "derive_secret_keys.h"

SessionFunction create_session(bool is_initiator, const Chunk &transcript,
                               const SecretKeys &secret_keys);
