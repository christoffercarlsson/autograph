#pragma once

bool decrypt_message(unsigned char *plaintext, const unsigned char *key,
                     const unsigned char *message,
                     const unsigned long long message_size);
