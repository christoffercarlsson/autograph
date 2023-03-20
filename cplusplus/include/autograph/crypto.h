#pragma once

#include <stdexcept>

#include "sodium.h"
#include "types.h"

Chunk decrypt(const Chunk &key, const uint32_t index, const Chunk &ciphertext);

Chunk encrypt(const Chunk &key, const uint32_t index, const Chunk &plaintext);

Chunk diffie_hellman(const Chunk &private_key, const Chunk &public_key);

Chunk hash(const Chunk &message, unsigned int iterations);

Chunk index_to_nonce(const uint32_t index);

Chunk kdf(const Chunk &ikm, const Byte context);

Chunk sign_message(const Chunk &private_key, const Chunk &message);

bool verify_signature(const Chunk &public_key, const Chunk &message,
                      const Chunk &signature);
