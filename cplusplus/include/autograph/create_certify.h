#pragma once

#include "crypto.h"

CertifyFunction create_certify(const Chunk &our_private_key,
                               const Chunk &their_public_key);
