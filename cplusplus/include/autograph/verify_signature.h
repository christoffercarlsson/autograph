#pragma once

bool verify_signature(const unsigned char *public_key,
                      const unsigned char *message,
                      unsigned long long message_size,
                      const unsigned char *signature);
