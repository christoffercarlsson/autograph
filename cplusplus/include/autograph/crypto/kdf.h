#pragma once

constexpr unsigned int autograph_crypto_kdf_KEY_SIZE = 32;

bool autograph_crypto_kdf(unsigned char *secret_key, const unsigned char *ikm,
                          const unsigned char context);
