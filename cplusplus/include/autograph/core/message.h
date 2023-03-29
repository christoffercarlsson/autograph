#pragma once

constexpr unsigned int autograph_core_message_EXTRA_SIZE = 20;

bool autograph_core_message_decrypt(unsigned char *plaintext,
                                    const unsigned char *key,
                                    const unsigned char *message,
                                    const unsigned long long message_size);

bool autograph_core_message_encrypt(unsigned char *ciphertext,
                                    const unsigned char *key,
                                    const unsigned char *plaintext,
                                    const unsigned long long plaintext_size);
