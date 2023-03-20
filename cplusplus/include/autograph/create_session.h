#pragma once

#include "create_certify.h"
#include "create_decrypt.h"
#include "create_encrypt.h"
#include "create_verify.h"
#include "verify_transcript.h"

SessionFunction create_session(const Chunk &our_private_key,
                               const Chunk &their_identity_key,
                               const Chunk &transcript,
                               const SecretKeys &secret_keys);
