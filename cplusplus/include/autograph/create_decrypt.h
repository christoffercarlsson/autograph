#pragma once

#include "types.h"

DecryptFunction create_decrypt(const Chunk &their_secret_key);
