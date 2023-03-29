#pragma once

const unsigned int autograph_crypto_sign_SIGNATURE_SIZE = 64;

bool autograph_crypto_sign(unsigned char *signature,
                           const unsigned char *private_key,
                           const unsigned char *message,
                           const unsigned long long message_size);

bool autograph_crypto_sign_verify(const unsigned char *public_key,
                                  const unsigned char *message,
                                  const unsigned long long message_size,
                                  const unsigned char *signature);
