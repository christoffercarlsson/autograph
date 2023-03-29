#pragma once

const unsigned int autograph_crypto_aes_NONCE_SIZE = 12;
const unsigned int autograph_crypto_aes_TAG_SIZE = 16;

bool autograph_crypto_aes_decrypt(unsigned char *plaintext,
                                  const unsigned char *key,
                                  const unsigned int index,
                                  const unsigned char *ciphertext,
                                  const unsigned long long ciphertext_size);

bool autograph_crypto_aes_encrypt(unsigned char *ciphertext,
                                  const unsigned char *key,
                                  const unsigned int index,
                                  const unsigned char *plaintext,
                                  const unsigned long long plaintext_size);
