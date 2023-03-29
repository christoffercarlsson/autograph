#pragma once

constexpr unsigned int autograph_crypto_hash_DIGEST_SIZE = 64;

bool autograph_crypto_hash(unsigned char *digest, const unsigned char *message,
                           const unsigned long long message_size,
                           const unsigned int iterations);
