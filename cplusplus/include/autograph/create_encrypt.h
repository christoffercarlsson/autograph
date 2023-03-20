#pragma once

#include "crypto.h"

EncryptFunction create_encrypt(const Chunk &our_secret_key);
