#pragma once

constexpr unsigned char autograph_crypto_diffie_hellman_OUTPUT_SIZE = 32;

bool autograph_crypto_diffie_hellman(unsigned char *shared_secret,
                                     const unsigned char *our_private_key,
                                     const unsigned char *their_public_key);
