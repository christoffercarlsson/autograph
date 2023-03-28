#pragma once

bool aes_decrypt(unsigned char *plaintext, const unsigned char *key,
                 const unsigned int index, const unsigned char *ciphertext,
                 const unsigned long long ciphertext_size);

bool aes_encrypt(unsigned char *ciphertext, const unsigned char *key,
                 const unsigned int index, const unsigned char *plaintext,
                 const unsigned long long plaintext_size);
