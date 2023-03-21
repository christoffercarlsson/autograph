#pragma once

#include "types.h"

EncryptFunction create_encrypt(const Chunk &our_secret_key);
