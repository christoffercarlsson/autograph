#pragma once

bool encrypt_message(unsigned char *ciphertext, const unsigned char *key,
                     const unsigned char *plaintext,
                     const unsigned long long plaintext_size);
