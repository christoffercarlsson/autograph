#pragma once

#include "crypto.h"

DecryptFunction create_decrypt(const Chunk &their_secret_key);
