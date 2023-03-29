#pragma once

const unsigned int autograph_core_key_pair_PRIVATE_KEY_SIZE = 32;
const unsigned int autograph_core_key_pair_PUBLIC_KEY_SIZE = 32;

int autograph_core_key_pair_ephemeral(unsigned char *private_key,
                                      unsigned char *public_key);

int autograph_core_key_pair_identity(unsigned char *private_key,
                                     unsigned char *public_key);
